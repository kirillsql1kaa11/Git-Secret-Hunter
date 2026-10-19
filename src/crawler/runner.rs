use super::github::GitHubRepo;
use super::stats::{CrawlerStats, RepoScanSummary};
use crate::git::{CollectLimits, GitEngine};
use crate::scanner::{group_findings, Scanner};
use indicatif::{ProgressBar, ProgressStyle};
use rayon::prelude::*;
use std::process::Command;
use std::time::Instant;
use tempfile::tempdir;

pub struct CrawlerRunner<'a> {
    scanner: &'a Scanner,
    depth: usize,
    concurrency: usize,
}

impl<'a> CrawlerRunner<'a> {
    pub fn new(scanner: &'a Scanner, depth: usize, concurrency: usize) -> Self {
        Self {
            scanner,
            depth,
            concurrency: concurrency.max(1),
        }
    }

    pub fn run(&self, repos: &[GitHubRepo]) -> CrawlerStats {
        let mut stats = CrawlerStats::new();
        let overall_start = Instant::now();

        let pb = ProgressBar::new(repos.len() as u64);
        pb.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.green} [{elapsed_precise}] [{bar:30.cyan/blue}] {pos}/{len} repos | {msg}")
                .unwrap()
                .progress_chars("#>-"),
        );

        let results = self.scan_repositories(repos, &pb);

        pb.finish_and_clear();

        for (repo, result) in repos.iter().zip(results) {
            match result {
                Some(summary) => stats.record_repo(
                    repo.full_name.clone(),
                    repo.html_url.clone(),
                    summary.duration_ms,
                    summary.findings,
                ),
                None => stats.record_failure(),
            }
        }

        stats.total_duration = overall_start.elapsed();
        stats
    }

    fn scan_repositories(
        &self,
        repos: &[GitHubRepo],
        pb: &ProgressBar,
    ) -> Vec<Option<RepoScanSummary>> {
        if repos.len() <= 1 || self.concurrency <= 1 {
            return repos
                .iter()
                .map(|repo| {
                    let result = self.scan_repo(repo, pb);
                    pb.inc(1);
                    result
                })
                .collect();
        }

        match rayon::ThreadPoolBuilder::new()
            .num_threads(self.concurrency.min(repos.len()))
            .build()
        {
            Ok(pool) => pool.install(|| {
                repos
                    .par_iter()
                    .map(|repo| {
                        let result = self.scan_repo(repo, pb);
                        pb.inc(1);
                        result
                    })
                    .collect()
            }),
            Err(_) => repos
                .iter()
                .map(|repo| {
                    let result = self.scan_repo(repo, pb);
                    pb.inc(1);
                    result
                })
                .collect(),
        }
    }

    fn scan_repo(&self, repo: &GitHubRepo, pb: &ProgressBar) -> Option<RepoScanSummary> {
        pb.set_message(format!("Auditing: {}", repo.full_name));

        self.scan_repo_detached(repo)
    }

    pub fn scan_repo_detached(&self, repo: &GitHubRepo) -> Option<RepoScanSummary> {
        let repo_start = Instant::now();

        let temp_dir = tempdir().ok()?;
        let target = temp_dir.path().to_str()?.to_string();

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
                &target,
            ])
            .output();

        let clone_ok = match clone_status {
            Ok(output) => output.status.success(),
            Err(_) => false,
        };

        if !clone_ok {
            return None;
        }

        let git_engine = GitEngine::new(temp_dir.path(), false, Some(self.depth), CollectLimits::default());
        let history = match git_engine.collect_all_commits() {
            Ok(history) => history,
            Err(_) => return None,
        };

        let mut findings = Vec::new();

        for commit in &history.commits {
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

        let unique_findings = group_findings(&findings).len();

        Some(RepoScanSummary {
            repo_name: repo.full_name.clone(),
            clone_url: repo.html_url.clone(),
            duration_ms: repo_start.elapsed().as_millis(),
            findings,
            unique_findings,
        })
    }
}
