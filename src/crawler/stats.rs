use crate::scanner::Finding;
use colored::*;
use serde::Serialize;
use std::collections::HashMap;
use std::time::Duration;

#[derive(Debug, Clone, Serialize)]
pub struct RepoScanSummary {
    pub repo_name: String,
    pub clone_url: String,
    pub duration_ms: u128,
    pub findings: Vec<Finding>,
}

#[derive(Debug, Default, Serialize)]
pub struct CrawlerStats {
    pub total_scanned: usize,
    pub successful_scans: usize,
    pub failed_clones: usize,
    pub repos_with_leaks: usize,
    pub total_findings: usize,
    pub category_counts: HashMap<String, usize>,
    pub rule_counts: HashMap<String, usize>,
    pub severity_counts: HashMap<String, usize>,
    pub repo_summaries: Vec<RepoScanSummary>,
    pub total_duration: Duration,
}

impl CrawlerStats {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record_repo(
        &mut self,
        repo_name: String,
        clone_url: String,
        duration: Duration,
        findings: Vec<Finding>,
    ) {
        self.total_scanned += 1;
        self.successful_scans += 1;

        if !findings.is_empty() {
            self.repos_with_leaks += 1;
            self.total_findings += findings.len();

            for f in &findings {
                *self
                    .category_counts
                    .entry(f.category.label().to_string())
                    .or_insert(0) += 1;
                *self.rule_counts.entry(f.rule_name.clone()).or_insert(0) += 1;
                *self
                    .severity_counts
                    .entry(f.severity.label().to_string())
                    .or_insert(0) += 1;
            }
        }

        self.repo_summaries.push(RepoScanSummary {
            repo_name,
            clone_url,
            duration_ms: duration.as_millis(),
            findings,
        });
    }

    pub fn record_failure(&mut self) {
        self.total_scanned += 1;
        self.failed_clones += 1;
    }

    pub fn print_dashboard(&self) {
        println!(
            "\n{}",
            "============================================================"
                .bright_cyan()
                .bold()
        );
        println!(
            "{}",
            "       GITHUB MASS AUDIT & LEAK RECON DASHBOARD             "
                .bright_yellow()
                .bold()
        );
        println!(
            "{}",
            "============================================================"
                .bright_cyan()
                .bold()
        );

        println!("\n{}", "[ METRICS OVERVIEW ]".bright_white().bold());
        println!("  Target Repositories:       {}", self.total_scanned.to_string().cyan());
        println!(
            "  Successfully Cloned:       {}",
            self.successful_scans.to_string().green()
        );
        println!(
            "  Failed Clones / Skipped:   {}",
            self.failed_clones.to_string().yellow()
        );

        let leak_ratio = if self.successful_scans > 0 {
            (self.repos_with_leaks as f64 / self.successful_scans as f64) * 100.0
        } else {
            0.0
        };

        println!(
            "  Compromised Repositories:  {} ({:.1}% of audited)",
            if self.repos_with_leaks > 0 {
                self.repos_with_leaks.to_string().red().bold()
            } else {
                "0".green()
            },
            leak_ratio
        );
        println!(
            "  Total Leaked Secrets:      {}",
            if self.total_findings > 0 {
                self.total_findings.to_string().red().bold()
            } else {
                "0".green()
            }
        );
        println!(
            "  Total Audit Time:          {:.2?}",
            self.total_duration
        );

        if self.successful_scans > 0 {
            let avg_per_repo = self.total_duration / self.successful_scans as u32;
            println!("  Average Speed Per Repo:    {:.2?}", avg_per_repo);
        }

        if !self.severity_counts.is_empty() {
            println!("\n{}", "[ FINDINGS BY SEVERITY ]".bright_white().bold());
            let critical = self.severity_counts.get("CRITICAL").copied().unwrap_or(0);
            let high = self.severity_counts.get("HIGH").copied().unwrap_or(0);
            let medium = self.severity_counts.get("MEDIUM").copied().unwrap_or(0);

            println!("  CRITICAL:  {}", critical.to_string().red().bold());
            println!("  HIGH:      {}", high.to_string().yellow().bold());
            println!("  MEDIUM:    {}", medium.to_string().blue());
        }

        if !self.rule_counts.is_empty() {
            println!("\n{}", "[ TOP LEAKED SECRET TYPES ]".bright_white().bold());
            let mut sorted_rules: Vec<(&String, &usize)> = self.rule_counts.iter().collect();
            sorted_rules.sort_by(|a, b| b.1.cmp(a.1));

            for (rule, count) in sorted_rules.iter().take(10) {
                println!("  - {:<36} : {}", rule.bright_magenta(), count.to_string().bold());
            }
        }

        let compromised_repos: Vec<&RepoScanSummary> = self
            .repo_summaries
            .iter()
            .filter(|r| !r.findings.is_empty())
            .collect();

        if !compromised_repos.is_empty() {
            println!(
                "\n{}",
                "[ REPOSITORIES WITH EXPOSED CREDENTIALS ]".bright_red().bold()
            );

            for summary in compromised_repos {
                println!(
                    "\n  * Repository: {}",
                    summary.repo_name.bright_yellow().bold()
                );
                println!("    URL:        {}", summary.clone_url.bright_black());
                println!(
                    "    Exposure:   {} secret(s) found in commit history",
                    summary.findings.len().to_string().red().bold()
                );

                for (idx, finding) in summary.findings.iter().enumerate().take(3) {
                    println!(
                        "      [#{}] {:<24} -> {} (file: {}:{})",
                        idx + 1,
                        finding.rule_name.cyan(),
                        finding.secret_preview.red(),
                        finding.file_path,
                        finding.line_number
                    );
                }

                if summary.findings.len() > 3 {
                    println!(
                        "      ... and {} more finding(s)",
                        summary.findings.len() - 3
                    );
                }
            }
        }

        println!(
            "\n{}",
            "============================================================"
                .bright_cyan()
                .bold()
        );
    }
}
