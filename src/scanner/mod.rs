pub mod candidates;
pub mod entropy;
pub mod filters;
pub mod grouping;
pub mod rules;

use candidates::extract_candidates;
use entropy::{analyze_candidate, calculate_shannon_entropy, classify_family};
use filters::{
    evaluate_context_lower, has_hash_context, has_secret_keyword, is_false_positive_token,
    is_ignored_path, ContextScore,
};
use rules::{RuleCategory, RuleRegistry};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
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
}

pub struct Scanner {
    pub registry: RuleRegistry,
    pub ai_only: bool,
    pub check_entropy: bool,
    pub entropy_threshold: f64,
    pub min_entropy_len: usize,
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
        }
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
            });
        }

        if self.check_entropy && !self.ai_only {
            for candidate in extract_candidates(line, self.min_entropy_len) {
                let candidate_lower = candidate.to_lowercase();

                if is_false_positive_token(&candidate_lower, hash_context) {
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
                });
            }
        }

        dedupe_line_findings(&mut findings);

        findings
    }
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
