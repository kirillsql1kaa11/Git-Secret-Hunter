use crate::scanner::Finding;
use crate::scanner::rules::{RuleCategory, Severity};
use crate::verify::{merge_verification, Verification};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Occurrence {
    pub commit_id: String,
    pub commit_author: String,
    pub commit_date: String,
    pub file_path: String,
    pub line_number: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingGroup {
    pub fingerprint: String,
    pub rule_id: String,
    pub rule_name: String,
    pub category: RuleCategory,
    pub severity: Severity,
    pub confidence: String,
    pub family: String,
    pub secret_preview: String,
    pub entropy: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verification: Option<Verification>,
    pub occurrences: Vec<Occurrence>,
    pub commit_count: usize,
    pub file_count: usize,
    pub first_seen: String,
    pub last_seen: String,
}

impl FindingGroup {
    pub fn is_failing(&self) -> bool {
        self.severity.rank() >= Severity::Low.rank()
    }

    pub fn files(&self) -> Vec<String> {
        let mut files: Vec<String> = Vec::new();
        for occurrence in &self.occurrences {
            if !files.contains(&occurrence.file_path) {
                files.push(occurrence.file_path.clone());
            }
        }
        files.sort();
        files
    }

    pub fn commits(&self) -> Vec<String> {
        let mut commits: Vec<String> = Vec::new();
        for occurrence in &self.occurrences {
            if !commits.contains(&occurrence.commit_id) {
                commits.push(occurrence.commit_id.clone());
            }
        }
        commits
    }
}

fn confidence_rank(confidence: &str) -> u8 {
    match confidence {
        "HIGH" => 3,
        "NORMAL" => 2,
        "LOW" => 1,
        _ => 0,
    }
}

fn preference(category: RuleCategory, severity: Severity, confidence: &str) -> (u8, u8, u8) {
    (
        u8::from(category.is_specific()),
        severity.rank(),
        confidence_rank(confidence),
    )
}

pub fn group_findings(findings: &[Finding]) -> Vec<FindingGroup> {
    let mut groups: Vec<FindingGroup> = Vec::new();
    let mut index: HashMap<String, usize> = HashMap::new();

    for finding in findings {
        let occurrence = Occurrence {
            commit_id: finding.commit_id.clone(),
            commit_author: finding.commit_author.clone(),
            commit_date: finding.commit_date.clone(),
            file_path: finding.file_path.clone(),
            line_number: finding.line_number,
        };

        match index.get(&finding.fingerprint) {
            Some(&position) => {
                let group = &mut groups[position];
                let duplicated = group.occurrences.iter().any(|existing| {
                    existing.commit_id == occurrence.commit_id
                        && existing.file_path == occurrence.file_path
                        && existing.line_number == occurrence.line_number
                });

                if !duplicated {
                    group.occurrences.push(occurrence);
                }

                let candidate_preference =
                    preference(finding.category, finding.severity, &finding.confidence);
                let current_preference =
                    preference(group.category, group.severity, &group.confidence);

                let candidate_wins = candidate_preference > current_preference
                    || (candidate_preference == current_preference
                        && finding.rule_id < group.rule_id);

                if candidate_wins {
                    group.rule_id = finding.rule_id.clone();
                    group.rule_name = finding.rule_name.clone();
                    group.category = finding.category;
                    group.severity = finding.severity;
                    group.confidence = finding.confidence.clone();
                    group.family = finding.family.clone();
                    group.secret_preview = finding.secret_preview.clone();
                    group.entropy = finding.entropy;
                }

                group.verification =
                    merge_verification(group.verification.as_ref(), finding.verification.as_ref());
            }
            None => {
                let position = groups.len();
                index.insert(finding.fingerprint.clone(), position);
                groups.push(FindingGroup {
                    fingerprint: finding.fingerprint.clone(),
                    rule_id: finding.rule_id.clone(),
                    rule_name: finding.rule_name.clone(),
                    category: finding.category,
                    severity: finding.severity,
                    confidence: finding.confidence.clone(),
                    family: finding.family.clone(),
                    secret_preview: finding.secret_preview.clone(),
                    entropy: finding.entropy,
                    verification: finding.verification.clone(),
                    occurrences: vec![occurrence],
                    commit_count: 0,
                    file_count: 0,
                    first_seen: String::new(),
                    last_seen: String::new(),
                });
            }
        }
    }

    for group in &mut groups {
        group.occurrences.sort_by(|a, b| {
            a.commit_date
                .cmp(&b.commit_date)
                .then_with(|| a.file_path.cmp(&b.file_path))
                .then_with(|| a.line_number.cmp(&b.line_number))
        });

        group.commit_count = group.commits().len();
        group.file_count = group.files().len();
        group.first_seen = group
            .occurrences
            .first()
            .map(|occurrence| occurrence.commit_date.clone())
            .unwrap_or_default();
        group.last_seen = group
            .occurrences
            .last()
            .map(|occurrence| occurrence.commit_date.clone())
            .unwrap_or_default();
    }

    groups.sort_by(|a, b| {
        b.severity
            .rank()
            .cmp(&a.severity.rank())
            .then_with(|| confidence_rank(&b.confidence).cmp(&confidence_rank(&a.confidence)))
            .then_with(|| a.rule_name.cmp(&b.rule_name))
            .then_with(|| a.fingerprint.cmp(&b.fingerprint))
    });

    groups
}
