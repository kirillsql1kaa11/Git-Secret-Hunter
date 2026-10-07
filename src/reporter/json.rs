use crate::scanner::Finding;
use serde::Serialize;
use std::time::Duration;

#[derive(Serialize)]
pub struct JsonReport {
    pub total_commits_scanned: usize,
    pub total_diff_lines: usize,
    pub scan_duration_ms: u128,
    pub total_findings: usize,
    pub findings: Vec<Finding>,
}

pub fn print_json(
    findings: Vec<Finding>,
    commits_scanned: usize,
    lines_scanned: usize,
    duration: Duration,
) {
    let report = JsonReport {
        total_commits_scanned: commits_scanned,
        total_diff_lines: lines_scanned,
        scan_duration_ms: duration.as_millis(),
        total_findings: findings.len(),
        findings,
    };

    if let Ok(json) = serde_json::to_string_pretty(&report) {
        println!("{}", json);
    }
}
