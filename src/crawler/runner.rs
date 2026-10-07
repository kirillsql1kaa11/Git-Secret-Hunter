use super::github::GitHubRepo;
use super::stats::CrawlerStats;
use crate::git::GitEngine;
use crate::scanner::Scanner;
use colored::*;
use indicatif::{ProgressBar, ProgressStyle};
use std::process::Command;
use std::time::Instant;
use tempfile::tempdir;

pub struct CrawlerRunner<'a> {
    scanner: &'a Scanner,
    depth: usize,
}

impl<'a> CrawlerRunner<'a> {
    pub fn new(scanner: &'a Scanner, depth: usize) -> Self {
        Self { scanner, depth }
    }

    pub fn run(&self, repos: &[GitHubRepo]) -> CrawlerStats {
        let total = repos.len();
        let mut stats = CrawlerStats::new();
        let overall_start = Instant::now();

        let pb = ProgressBar::new(total as u64);
        pb.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.green} [{elapsed_precise}] [{bar:30.cyan/blue}] {pos}/{len} repos | {msg}")
                .unwrap()
                .progress_chars("#>-"),
        );

        for repo in repos {
            pb.set_message(format!(
                "Auditing: {} (leaks found: {})",
                repo.full_name.yellow(),
                stats.total_findings.to_string().red()
            ));

            let repo_start = Instant::now();
            let temp_dir = match tempdir() {
                Ok(td) => td,
                Err(_) => {
                    stats.record_failure();
                    pb.inc(1);
                    continue;
                }
            };

            let clone_status = Command::new("git")
                .args([
                    "clone",
                    "--depth",
                    &self.depth.to_string(),
                    "--single-branch",
                    "--filter=blob:limit=512k",
                    "-c",
                    "http.lowSpeedLimit=1000",
                    "-c",
                    "http.lowSpeedTime=10",
                    "--quiet",
                    &repo.clone_url(),
                    temp_dir.path().to_str().unwrap_or("."),
                ])
                .output();

            let clone_ok = match clone_status {
                Ok(output) => output.status.success(),
                Err(_) => false,
            };

            if !clone_ok {
                stats.record_failure();
                pb.inc(1);
                continue;
            }

            let git_engine = GitEngine::new(temp_dir.path(), false, Some(self.depth));
            let commits = match git_engine.collect_all_commits() {
                Ok(c) => c,
                Err(_) => {
                    stats.record_failure();
                    pb.inc(1);
                    continue;
                }
            };

            let mut findings = Vec::new();
            for commit in &commits {
                for diff_line in &commit.added_lines {
                    let found = self.scanner.scan_line(
                        &diff_line.content,
                        &diff_line.file_path,
                        diff_line.line_number,
                        &commit.commit_id,
                        &commit.author,
                        &commit.date,
                    );
                    findings.extend(found);
                }
            }

            let repo_duration = repo_start.elapsed();
            stats.record_repo(
                repo.full_name.clone(),
                repo.html_url.clone(),
                repo_duration,
                findings,
            );

            pb.inc(1);
        }

        pb.finish_and_clear();
        stats.total_duration = overall_start.elapsed();
        stats
    }
}
