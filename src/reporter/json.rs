use crate::scanner::{Finding, FindingGroup};
use serde::Serialize;
use std::time::Duration;

pub const SCHEMA_VERSION: u32 = 1;

#[derive(Serialize)]
pub struct JsonReport {
    pub schema_version: u32,
    pub tool_version: &'static str,
    pub repo_path: String,
    pub total_commits_scanned: usize,
    pub total_diff_lines: usize,
    pub skipped_lines: usize,
    pub skipped_files: usize,
    pub scan_duration_ms: u128,
    pub total_findings: usize,
    pub unique_findings: usize,
    pub findings: Vec<Finding>,
    pub groups: Vec<FindingGroup>,
}

pub struct ReportMeta {
    pub repo_path: String,
    pub commits_scanned: usize,
    pub lines_scanned: usize,
    pub skipped_lines: usize,
    pub skipped_files: usize,
    pub duration: Duration,
}

pub fn build_report(
    findings: &[Finding],
    groups: &[FindingGroup],
    meta: ReportMeta,
) -> JsonReport {
    JsonReport {
        schema_version: SCHEMA_VERSION,
        tool_version: env!("CARGO_PKG_VERSION"),
        repo_path: meta.repo_path,
        total_commits_scanned: meta.commits_scanned,
        total_diff_lines: meta.lines_scanned,
        skipped_lines: meta.skipped_lines,
        skipped_files: meta.skipped_files,
        scan_duration_ms: meta.duration.as_millis(),
        total_findings: findings.len(),
        unique_findings: groups.len(),
        findings: findings.to_vec(),
        groups: groups.to_vec(),
    }
}

pub fn print_json(
    findings: &[Finding],
    groups: &[FindingGroup],
    repo_path: &str,
    commits_scanned: usize,
    lines_scanned: usize,
    skipped_lines: usize,
    skipped_files: usize,
    duration: Duration,
) {
    let report = build_report(
        findings,
        groups,
        ReportMeta {
            repo_path: repo_path.to_string(),
            commits_scanned,
            lines_scanned,
            skipped_lines,
            skipped_files,
            duration,
        },
    );

    if let Ok(json) = serde_json::to_string_pretty(&report) {
        println!("{}", json);
    }
}
