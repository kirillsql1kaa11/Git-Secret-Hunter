pub mod entropy;
pub mod filters;
pub mod rules;

use entropy::{calculate_shannon_entropy, is_candidate_entropy_token};
use filters::{evaluate_context, is_false_positive_token, is_ignored_path, ContextScore};
use rules::{RuleCategory, RuleRegistry, Severity};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub rule_id: String,
    pub rule_name: String,
    pub category: RuleCategory,
    pub severity: Severity,
    pub confidence: String,
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

        let mut findings = Vec::new();

        for rule in &self.registry.rules {
            for m in rule.regex.find_iter(line) {
                let matched_text = m.as_str();

                let context_score = evaluate_context(line, file_path, matched_text);
                if context_score == ContextScore::FalsePositive {
                    continue;
                }

                let severity = match context_score {
                    ContextScore::LowConfidence => Severity::Low,
                    _ => rule.severity,
                };

                let confidence = match context_score {
                    ContextScore::HighConfidence => "HIGH".to_string(),
                    ContextScore::Normal => "NORMAL".to_string(),
                    ContextScore::LowConfidence => "LOW".to_string(),
                    ContextScore::FalsePositive => "NONE".to_string(),
                };

                let ent = calculate_shannon_entropy(matched_text);
                let preview = mask_secret(matched_text);

                findings.push(Finding {
                    rule_id: rule.id.to_string(),
                    rule_name: rule.name.to_string(),
                    category: rule.category,
                    severity,
                    confidence,
                    secret_preview: preview,
                    commit_id: commit_id.to_string(),
                    commit_author: commit_author.to_string(),
                    commit_date: commit_date.to_string(),
                    file_path: file_path.to_string(),
                    line_number,
                    entropy: Some(ent),
                });
            }
        }

        if self.check_entropy {
            for word in line.split_whitespace() {
                if is_candidate_entropy_token(word, self.min_entropy_len) {
                    let cleaned = word.trim_matches(|c: char| {
                        c == '"'
                            || c == '\''
                            || c == '`'
                            || c == ';'
                            || c == ','
                            || c == ':'
                            || c == '('
                            || c == ')'
                            || c == '{'
                            || c == '}'
                            || c == '['
                            || c == ']'
                            || c == '<'
                            || c == '>'
                            || c == '='
                    });

                    let context_score = evaluate_context(line, file_path, cleaned);
                    if context_score == ContextScore::FalsePositive {
                        continue;
                    }

                    if is_false_positive_token(cleaned) {
                        continue;
                    }

                    let ent = calculate_shannon_entropy(cleaned);
                    if ent >= self.entropy_threshold {
                        let already_found = findings
                            .iter()
                            .any(|f| f.secret_preview.contains(&cleaned[..cleaned.len().min(6)]));

                        if !already_found {
                            let severity = match context_score {
                                ContextScore::LowConfidence => Severity::Low,
                                _ => Severity::Medium,
                            };

                            let confidence = match context_score {
                                ContextScore::HighConfidence => "HIGH".to_string(),
                                ContextScore::Normal => "NORMAL".to_string(),
                                ContextScore::LowConfidence => "LOW".to_string(),
                                ContextScore::FalsePositive => "NONE".to_string(),
                            };

                            findings.push(Finding {
                                rule_id: "high-entropy-token".to_string(),
                                rule_name: "High Entropy Random Secret".to_string(),
                                category: RuleCategory::GenericEntropy,
                                severity,
                                confidence,
                                secret_preview: mask_secret(cleaned),
                                commit_id: commit_id.to_string(),
                                commit_author: commit_author.to_string(),
                                commit_date: commit_date.to_string(),
                                file_path: file_path.to_string(),
                                line_number,
                                entropy: Some(ent),
                            });
                        }
                    }
                }
            }
        }

        findings
    }
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
