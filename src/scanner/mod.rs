pub mod candidates;
pub mod entropy;
pub mod filters;
pub mod grouping;
pub mod rules;

use candidates::extract_candidates;
use entropy::{analyze_candidate, calculate_shannon_entropy, classify_family};
use crate::verify::Verification;
use filters::{
    evaluate_context_lower, has_hash_context, has_secret_keyword, is_false_positive_token,
    is_ignored_path, looks_like_artifact_name, looks_like_checksum_line, looks_like_minified_line,
    ContextScore,
};
use rules::{RuleCategory, RuleRegistry};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fmt::Write as _;

pub use grouping::{FindingGroup, Occurrence, group_findings};
pub use rules::Severity;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub rule_id: String,
    pub rule_name: String,
    pub category: RuleCategory,
    pub severity: Severity,
    pub confidence: String,
    pub fingerprint: String,
    pub family: String,
    pub secret_preview: String,
    pub commit_id: String,
    pub commit_author: String,
    pub commit_date: String,
    pub file_path: String,
    pub line_number: usize,
    pub entropy: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verification: Option<Verification>,
    #[serde(skip)]
    pub secret: Option<String>,
}

pub struct Scanner {
    pub registry: RuleRegistry,
    pub ai_only: bool,
    pub check_entropy: bool,
    pub entropy_threshold: f64,
    pub min_entropy_len: usize,
    pub capture_secrets: bool,
    pub verify_online: bool,
}

impl Scanner {
    pub fn new(
        ai_only: bool,
        check_entropy: bool,
        entropy_threshold: f64,
        min_entropy_len: usize,
    ) -> Self {
        Self {
            registry: RuleRegistry::new(ai_only),
            ai_only,
            check_entropy,
            entropy_threshold,
            min_entropy_len,
            capture_secrets: false,
            verify_online: false,
        }
    }

    pub fn with_verification(mut self, enabled: bool) -> Self {
        self.verify_online = enabled;

        if enabled {
            self.capture_secrets = true;
        }

        self
    }

    pub fn scan_line(
        &self,
        line: &str,
        file_path: &str,
        line_number: usize,
        commit_id: &str,
        commit_author: &str,
        commit_date: &str,
    ) -> Vec<Finding> {
        if is_ignored_path(file_path) {
            return Vec::new();
        }

        if looks_like_checksum_line(line) {
            return Vec::new();
        }

        let line_lower = line.to_lowercase();
        let path_lower = file_path.to_lowercase();
        let hash_context = has_hash_context(&line_lower);
        let secret_keyword = has_secret_keyword(&line_lower);
        let mut findings = Vec::new();

        let mut matches: Vec<(&rules::DetectionRule, String, usize)> = Vec::new();

        for position in self.registry.matching_indices(line) {
            let rule = &self.registry.rules[position];

            for matched in rule.regex.find_iter(line) {
                if matched.as_str().is_empty() {
                    continue;
                }

                matches.push((rule, matched.as_str().to_string(), matched.start()));
            }
        }

        let specific_spans: Vec<(usize, usize)> = matches
            .iter()
            .filter(|(rule, _, _)| rule.category.is_specific())
            .map(|(_, value, start)| (*start, *start + value.len()))
            .collect();

        matches.retain(|(rule, value, start)| {
            rule.category.is_specific()
                || !specific_spans
                    .iter()
                    .any(|(span_start, span_end)| start >= span_start && start + value.len() <= *span_end)
        });

        for (rule, value, _) in &matches {
            let context = evaluate_context_lower(&line_lower, &path_lower, &value.to_lowercase());

            if context == ContextScore::FalsePositive {
                continue;
            }

            if rule.suppress_in_hash_context {
                if hash_context && !secret_keyword {
                    continue;
                }

                if calculate_shannon_entropy(value) < 3.0 {
                    continue;
                }

                if is_false_positive_token(&value.to_lowercase(), hash_context) {
                    continue;
                }

                if value.eq_ignore_ascii_case(commit_id) {
                    continue;
                }
            }

            let severity = if context == ContextScore::LowConfidence {
                Severity::Low
            } else {
                rule.severity
            };

            findings.push(Finding {
                rule_id: rule.id.to_string(),
                rule_name: rule.name.to_string(),
                category: rule.category,
                severity,
                confidence: context_label(context).to_string(),
                fingerprint: fingerprint_of(value),
                family: classify_family(value).label().to_string(),
                secret_preview: mask_secret(value),
                commit_id: commit_id.to_string(),
                commit_author: commit_author.to_string(),
                commit_date: commit_date.to_string(),
                file_path: file_path.to_string(),
                line_number,
                entropy: Some(calculate_shannon_entropy(value)),
                verification: None,
                secret: self.capture_secrets.then(|| value.to_string()),
            });
        }

        if self.check_entropy && !self.ai_only && !looks_like_minified_line(line) {
            for candidate in extract_candidates(line, self.min_entropy_len) {
                let candidate_lower = candidate.to_lowercase();

                if is_false_positive_token(&candidate_lower, hash_context) {
                    continue;
                }

                if looks_like_artifact_name(&candidate_lower) {
                    continue;
                }

                if candidate.eq_ignore_ascii_case(commit_id) {
                    continue;
                }

                let analysis = match analyze_candidate(&candidate, self.entropy_threshold, secret_keyword) {
                    Some(analysis) => analysis,
                    None => continue,
                };

                if findings
                    .iter()
                    .any(|finding| finding.fingerprint == fingerprint_of(&candidate))
                {
                    continue;
                }

                let context = evaluate_context_lower(&line_lower, &path_lower, &candidate_lower);

                if context == ContextScore::FalsePositive {
                    continue;
                }

                let severity = match context {
                    ContextScore::LowConfidence => Severity::Low,
                    ContextScore::HighConfidence => Severity::High,
                    _ => Severity::Medium,
                };

                findings.push(Finding {
                    rule_id: "high-entropy-token".to_string(),
                    rule_name: "High Entropy Random Secret".to_string(),
                    category: RuleCategory::GenericEntropy,
                    severity,
                    confidence: context_label(context).to_string(),
                    fingerprint: fingerprint_of(&candidate),
                    family: analysis.family.label().to_string(),
                    secret_preview: mask_secret(&candidate),
                    commit_id: commit_id.to_string(),
                    commit_author: commit_author.to_string(),
                    commit_date: commit_date.to_string(),
                    file_path: file_path.to_string(),
                    line_number,
                    entropy: Some(analysis.entropy),
                    verification: None,
                    secret: self.capture_secrets.then(|| candidate.clone()),
                });
            }
        }

        dedupe_line_findings(&mut findings);

        findings
    }

    pub fn scan_file_lines(
        &self,
        lines: &[(usize, &str)],
        file_path: &str,
        commit_id: &str,
        commit_author: &str,
        commit_date: &str,
    ) -> Vec<Finding> {
        if is_ignored_path(file_path) {
            return Vec::new();
        }

        let mut findings = Vec::new();

        for (line_number, content) in lines {
            findings.extend(self.scan_line(
                content,
                file_path,
                *line_number,
                commit_id,
                commit_author,
                commit_date,
            ));
        }

        let block_findings = self.scan_blocks(lines, file_path, commit_id, commit_author, commit_date);
        let blocked_lines: HashSet<usize> = block_findings
            .iter()
            .filter(|finding| finding.rule_id == "private-key-material")
            .map(|finding| finding.line_number)
            .collect();

        findings.retain(|finding| {
            !(finding.rule_id == "private-key" && blocked_lines.contains(&finding.line_number))
        });
        findings.extend(block_findings);

        let mut seen: HashSet<(String, String, usize)> = HashSet::new();
        findings.retain(|finding| {
            seen.insert((
                finding.rule_id.clone(),
                finding.fingerprint.clone(),
                finding.line_number,
            ))
        });

        findings
    }

    fn scan_blocks(
        &self,
        lines: &[(usize, &str)],
        file_path: &str,
        commit_id: &str,
        commit_author: &str,
        commit_date: &str,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut index = 0;

        while index < lines.len() {
            let line_number = lines[index].0;

            if let Some((end, material)) = collect_pem_block(lines, index) {
                findings.push(self.block_finding(
                    "private-key-material",
                    "Private Key Material",
                    RuleCategory::CryptographicKey,
                    Severity::Critical,
                    &material,
                    "HIGH",
                    "Base64",
                    file_path,
                    line_number,
                    commit_id,
                    commit_author,
                    commit_date,
                ));
                index = end + 1;
                continue;
            }

            if let Some((end, key, body)) = collect_yaml_block(lines, index) {
                findings.extend(self.scan_block_body(
                    &key,
                    &body,
                    file_path,
                    commit_id,
                    commit_author,
                    commit_date,
                ));
                index = end + 1;
                continue;
            }

            if let Some((end, key, body)) = collect_toml_block(lines, index) {
                findings.extend(self.scan_block_body(
                    &key,
                    &body,
                    file_path,
                    commit_id,
                    commit_author,
                    commit_date,
                ));
                index = end + 1;
                continue;
            }

            index += 1;
        }

        findings
    }

    fn scan_block_body(
        &self,
        key: &str,
        body: &[(usize, String)],
        file_path: &str,
        commit_id: &str,
        commit_author: &str,
        commit_date: &str,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();

        for (line_number, content) in body {
            if content.trim().is_empty() {
                continue;
            }

            let synthetic = format!("{}: {}", key, content);
            findings.extend(self.scan_line(
                &synthetic,
                file_path,
                *line_number,
                commit_id,
                commit_author,
                commit_date,
            ));
        }

        let joined: String = body
            .iter()
            .map(|(_, content)| content.trim())
            .collect::<Vec<_>>()
            .join("");

        if joined.len() >= self.min_entropy_len {
            let synthetic = format!("{}: {}", key, joined);

            if let Some((first_line, _)) = body.first() {
                findings.extend(self.scan_line(
                    &synthetic,
                    file_path,
                    *first_line,
                    commit_id,
                    commit_author,
                    commit_date,
                ));
            }
        }

        findings
    }

    #[allow(clippy::too_many_arguments)]
    fn block_finding(
        &self,
        rule_id: &str,
        rule_name: &str,
        category: RuleCategory,
        severity: Severity,
        secret: &str,
        confidence: &str,
        family: &str,
        file_path: &str,
        line_number: usize,
        commit_id: &str,
        commit_author: &str,
        commit_date: &str,
    ) -> Finding {
        Finding {
            rule_id: rule_id.to_string(),
            rule_name: rule_name.to_string(),
            category,
            severity,
            confidence: confidence.to_string(),
            fingerprint: fingerprint_of(secret),
            family: family.to_string(),
            secret_preview: mask_secret(secret),
            commit_id: commit_id.to_string(),
            commit_author: commit_author.to_string(),
            commit_date: commit_date.to_string(),
            file_path: file_path.to_string(),
            line_number,
            entropy: Some(calculate_shannon_entropy(secret)),
            verification: None,
            secret: self.capture_secrets.then(|| secret.to_string()),
        }
    }
}

fn indentation(line: &str) -> usize {
    line.chars().take_while(|c| *c == ' ' || *c == '\t').count()
}

fn yaml_block_key(line: &str) -> Option<String> {
    let trimmed = line.trim_end();
    let colon = trimmed.rfind(':')?;
    let key = trimmed[..colon].trim();
    let value = trimmed[colon + 1..].trim();
    let mut chars = value.chars();
    let indicator = chars.next()?;

    if indicator != '|' && indicator != '>' {
        return None;
    }

    if key.is_empty() || key.starts_with('#') {
        return None;
    }

    if !chars.all(|character| character.is_ascii_digit() || character == '-' || character == '+') {
        return None;
    }

    Some(key.to_string())
}

fn collect_yaml_block(
    lines: &[(usize, &str)],
    start: usize,
) -> Option<(usize, String, Vec<(usize, String)>)> {
    let key = yaml_block_key(lines[start].1)?;
    let base_indent = indentation(lines[start].1);
    let mut body = Vec::new();
    let mut end = start;
    let mut bytes = 0;

    for (offset, (line_number, line)) in lines.iter().enumerate().skip(start + 1).take(200) {
        if !line.trim().is_empty() && indentation(line) <= base_indent {
            break;
        }

        if !line.trim().is_empty() {
            body.push((*line_number, line.trim().to_string()));
            bytes += line.len();
            end = offset;
        }

        if bytes > 16384 {
            break;
        }
    }

    if body.is_empty() {
        return None;
    }

    Some((end, key, body))
}

fn toml_block_header(line: &str) -> Option<(String, &'static str)> {
    let triple_double = line.matches("\"\"\"").count();
    let triple_single = line.matches("'''").count();

    let marker = if triple_double % 2 == 1 {
        "\"\"\""
    } else if triple_single % 2 == 1 {
        "'''"
    } else {
        return None;
    };

    let position = line.rfind(marker)?;
    let key = line[..position].trim().trim_end_matches('=').trim();

    if key.is_empty() || key.starts_with('#') {
        return None;
    }

    Some((key.to_string(), marker))
}

fn collect_toml_block(
    lines: &[(usize, &str)],
    start: usize,
) -> Option<(usize, String, Vec<(usize, String)>)> {
    let (key, marker) = toml_block_header(lines[start].1)?;
    let after_opening = lines[start].1.rfind(marker)? + marker.len();
    let mut body = Vec::new();
    let mut bytes = 0;
    let mut end = None;

    let same_line = lines[start].1[after_opening..].trim();

    if !same_line.is_empty() {
        body.push((lines[start].0, same_line.to_string()));
    }

    for (offset, (line_number, line)) in lines.iter().enumerate().skip(start + 1).take(200) {
        if line.contains(marker) {
            let before = line.split(marker).next().unwrap_or("");

            if !before.trim().is_empty() {
                body.push((*line_number, before.trim().to_string()));
            }

            end = Some(offset);
            break;
        }

        body.push((*line_number, line.trim().to_string()));
        bytes += line.len();

        if bytes > 16384 {
            break;
        }
    }

    let end = end?;

    if body.is_empty() {
        return None;
    }

    Some((end, key, body))
}

fn pem_private_key_header(line: &str) -> bool {
    let trimmed = line.trim();
    let Some(begin) = trimmed.find("-----BEGIN ") else {
        return false;
    };

    let after_begin = &trimmed[begin + "-----BEGIN ".len()..];

    let Some(marker_end) = after_begin.find("-----") else {
        return false;
    };

    let label = &after_begin[..marker_end];

    if label.is_empty() || label.len() > 64 {
        return false;
    }

    if !label.contains("PRIVATE KEY") {
        return false;
    }

    if !label
        .chars()
        .all(|character| character.is_ascii_uppercase() || character == ' ')
    {
        return false;
    }

    let rest = after_begin[marker_end + 5..].trim();

    rest.chars().all(|character| {
        character == '"'
            || character == '\''
            || character == ','
            || character == ';'
            || character == '#'
            || character == '%'
    })
}

fn collect_pem_block(lines: &[(usize, &str)], start: usize) -> Option<(usize, String)> {
    if !pem_private_key_header(lines[start].1) {
        return None;
    }

    let mut material = String::new();
    let mut end = None;

    for (offset, (_, line)) in lines.iter().enumerate().skip(start + 1).take(400) {
        let trimmed = line.trim();

        if trimmed.starts_with("-----END ") {
            end = Some(offset);
            break;
        }

        if !trimmed.is_empty() {
            let is_base64 = trimmed.chars().all(|character| {
                character.is_ascii_alphanumeric()
                    || character == '+'
                    || character == '/'
                    || character == '='
            });

            if !is_base64 {
                return None;
            }

            material.push_str(trimmed);
        }

        if material.len() > 32768 {
            end = Some(offset);
            break;
        }
    }

    let end = end?;

    if material.len() < 64 {
        return None;
    }

    Some((end, material))
}

fn dedupe_line_findings(findings: &mut Vec<Finding>) {
    let specific: Vec<String> = findings
        .iter()
        .filter(|finding| finding.category.is_specific())
        .map(|finding| finding.fingerprint.clone())
        .collect();

    let mut seen: Vec<(String, String)> = Vec::new();

    findings.retain(|finding| {
        if !finding.category.is_specific() && specific.contains(&finding.fingerprint) {
            return false;
        }

        let key = (finding.rule_id.clone(), finding.fingerprint.clone());
        if seen.contains(&key) {
            return false;
        }

        seen.push(key);
        true
    });
}

fn context_label(context: ContextScore) -> &'static str {
    match context {
        ContextScore::HighConfidence => "HIGH",
        ContextScore::Normal => "NORMAL",
        ContextScore::LowConfidence => "LOW",
        ContextScore::FalsePositive => "NONE",
    }
}

pub fn fingerprint_of(secret: &str) -> String {
    let digest = Sha256::digest(secret.as_bytes());
    let mut fingerprint = String::with_capacity(16);

    for byte in &digest[..8] {
        let _ = write!(fingerprint, "{:02x}", byte);
    }

    fingerprint
}

pub fn mask_secret(secret: &str) -> String {
    let len = secret.chars().count();
    if len <= 8 {
        return "***".to_string();
    }

    let prefix: String = secret.chars().take(6).collect();
    let suffix: String = secret.chars().skip(len - 4).collect();
    format!("{}...{}", prefix, suffix)
}
