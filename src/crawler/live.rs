use super::github::{CrawlFilters, GitHubClient, GitHubRepo};
use super::runner::CrawlerRunner;
use super::state::CrawlSeen;
use crate::scanner::{Finding, FindingGroup, Scanner, group_findings};
use rayon::prelude::*;
use serde::Serialize;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct CrawlOptions {
    pub limit: usize,
    pub depth: usize,
    pub concurrency: usize,
    pub query: Option<String>,
    pub token: Option<String>,
    pub ai_only: bool,
    pub entropy_threshold: f64,
    pub min_entropy_len: usize,
    pub filters: CrawlFilters,
    pub skip_seen: bool,
    pub remember_seen: bool,
    pub verify: bool,
}

impl Default for CrawlOptions {
    fn default() -> Self {
        Self {
            limit: 20,
            depth: 50,
            concurrency: 4,
            query: None,
            token: std::env::var("GITHUB_TOKEN")
                .ok()
                .filter(|token| !token.trim().is_empty()),
            ai_only: false,
            entropy_threshold: 4.5,
            min_entropy_len: 24,
            filters: CrawlFilters::default(),
            skip_seen: true,
            remember_seen: true,
            verify: false,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct CrawlTotals {
    pub discovered: usize,
    pub scanned: usize,
    pub failed: usize,
    pub skipped: usize,
    pub skipped_known: usize,
    pub repos_with_leaks: usize,
    pub unique_findings: usize,
    pub failing_findings: usize,
    pub duration: Duration,
}

#[derive(Debug, Clone)]
pub struct CrawledRepo {
    pub repo_name: String,
    pub clone_url: String,
    pub duration_ms: u128,
    pub failing_findings: usize,
    pub groups: Vec<FindingGroup>,
    pub findings: Vec<Finding>,
}

impl CrawledRepo {
    pub fn max_severity_rank(&self) -> u8 {
        self.groups
            .iter()
            .map(|group| group.severity.rank())
            .max()
            .unwrap_or(0)
    }
}

pub enum CrawlEvent {
    Discovered {
        total: usize,
        query: Option<String>,
        skipped_known: usize,
    },
    Started {
        repo_name: String,
    },
    Scanned(Box<CrawledRepo>),
    Failed {
        repo_name: String,
    },
    Finished(Box<CrawlTotals>),
    Error(String),
}

enum RepoOutcome {
    Scanned { failing_findings: usize },
    Failed,
    Skipped,
}

pub struct CrawlHandle {
    pub started: Instant,
    cancel: Arc<AtomicBool>,
    receiver: Receiver<CrawlEvent>,
}

impl CrawlHandle {
    pub fn cancel(&self) {
        self.cancel.store(true, Ordering::Relaxed);
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancel.load(Ordering::Relaxed)
    }

    pub fn poll(&self) -> Option<CrawlEvent> {
        self.receiver.try_recv().ok()
    }
}

pub fn spawn_crawl<F>(options: CrawlOptions, notify: F) -> CrawlHandle
where
    F: Fn() + Send + Sync + 'static,
{
    let (sender, receiver): (Sender<CrawlEvent>, Receiver<CrawlEvent>) = channel();
    let cancel = Arc::new(AtomicBool::new(false));
    let cancel_for_thread = Arc::clone(&cancel);

    let handle = CrawlHandle {
        started: Instant::now(),
        cancel,
        receiver,
    };

    std::thread::spawn(move || {
        let emit = |event: CrawlEvent| {
            let _ = sender.send(event);
            notify();
        };

        if let Err(error) = crawl_core(&options, &cancel_for_thread, &emit) {
            emit(CrawlEvent::Error(error));
        }
    });

    handle
}

pub fn run_crawl_blocking(
    options: &CrawlOptions,
    on_event: &(dyn Fn(CrawlEvent) + Send + Sync),
) -> Result<CrawlTotals, String> {
    crawl_core(options, &AtomicBool::new(false), on_event)
}

pub fn crawl_core(
    options: &CrawlOptions,
    cancel: &AtomicBool,
    on_event: &(dyn Fn(CrawlEvent) + Send + Sync),
) -> Result<CrawlTotals, String> {
    let started = Instant::now();

    let client = GitHubClient::new(options.token.as_deref())?;

    let query = options
        .query
        .as_ref()
        .map(|query| query.trim().to_string())
        .filter(|query| !query.is_empty());

    let mut seen = (options.skip_seen || options.remember_seen).then(CrawlSeen::load);
    let exclude = seen.as_ref().map(CrawlSeen::as_set).unwrap_or_default();

    let discovery = client.discover(query.as_deref(), options.limit, &options.filters, &exclude)?;

    let total = discovery.repos.len();
    on_event(CrawlEvent::Discovered {
        total,
        query: query.clone(),
        skipped_known: discovery.skipped,
    });

    let scanner = Scanner::new(
        options.ai_only,
        true,
        options.entropy_threshold,
        options.min_entropy_len,
    )
    .with_verification(options.verify);

    let runner = CrawlerRunner::new(&scanner, options.depth, options.concurrency);
    let recorded: Mutex<Vec<String>> = Mutex::new(Vec::new());

    let process = |repo: &GitHubRepo| -> RepoOutcome {
        if cancel.load(Ordering::Relaxed) {
            return RepoOutcome::Skipped;
        }

        on_event(CrawlEvent::Started {
            repo_name: repo.full_name.clone(),
        });

        let outcome = match runner.scan_repo_detached(repo) {
            Some(summary) => {
                let groups = group_findings(&summary.findings);
                let failing_findings = groups.iter().filter(|group| group.is_failing()).count();

                on_event(CrawlEvent::Scanned(Box::new(CrawledRepo {
                    repo_name: repo.full_name.clone(),
                    clone_url: repo.html_url.clone(),
                    duration_ms: summary.duration_ms,
                    failing_findings,
                    groups,
                    findings: summary.findings,
                })));

                RepoOutcome::Scanned { failing_findings }
            }
            None => {
                on_event(CrawlEvent::Failed {
                    repo_name: repo.full_name.clone(),
                });

                RepoOutcome::Failed
            }
        };

        if options.remember_seen {
            if let Ok(mut recorded) = recorded.lock() {
                recorded.push(repo.full_name.clone());
            }
        }

        outcome
    };

    let concurrency = options.concurrency.max(1);
    let outcomes: Vec<RepoOutcome> = if concurrency <= 1 || total <= 1 {
        discovery.repos.iter().map(process).collect()
    } else {
        match rayon::ThreadPoolBuilder::new()
            .num_threads(concurrency.min(total))
            .build()
        {
            Ok(pool) => pool.install(|| discovery.repos.par_iter().map(process).collect()),
            Err(_) => discovery.repos.iter().map(process).collect(),
        }
    };

    let mut totals = CrawlTotals {
        discovered: total,
        skipped_known: discovery.skipped,
        ..CrawlTotals::default()
    };

    for outcome in outcomes {
        match outcome {
            RepoOutcome::Scanned { failing_findings } => {
                totals.scanned += 1;

                if failing_findings > 0 {
                    totals.repos_with_leaks += 1;
                }
            }
            RepoOutcome::Failed => totals.failed += 1,
            RepoOutcome::Skipped => totals.skipped += 1,
        }
    }

    if options.remember_seen {
        let names = recorded
            .lock()
            .map(|recorded| recorded.clone())
            .unwrap_or_default();

        if !names.is_empty() {
            let store = seen.get_or_insert_with(CrawlSeen::load);

            for name in names {
                store.record(&name);
            }

            store.save();
        }
    }

    totals.duration = started.elapsed();

    on_event(CrawlEvent::Finished(Box::new(totals.clone())));

    Ok(totals)
}

#[derive(Serialize)]
pub struct CrawlFiltersReport {
    pub min_stars: u32,
    pub max_size_kb: Option<u64>,
    pub language: Option<String>,
    pub include_forks: bool,
    pub include_archived: bool,
    pub pushed_days: Option<u32>,
}

#[derive(Serialize)]
pub struct CrawlReport {
    pub schema_version: u32,
    pub tool_version: &'static str,
    pub mode: &'static str,
    pub query: Option<String>,
    pub depth: usize,
    pub concurrency: usize,
    pub verify: bool,
    pub filters: CrawlFiltersReport,
    pub discovered: usize,
    pub scanned: usize,
    pub failed: usize,
    pub skipped: usize,
    pub skipped_known: usize,
    pub repos_with_leaks: usize,
    pub unique_findings: usize,
    pub failing_findings: usize,
    pub verified_findings: usize,
    pub duration_ms: u128,
    pub repos: Vec<CrawlRepoReport>,
}

#[derive(Serialize)]
pub struct CrawlRepoReport {
    pub repo_name: String,
    pub clone_url: String,
    pub duration_ms: u128,
    pub unique_findings: usize,
    pub failing_findings: usize,
    pub findings: Vec<Finding>,
    pub groups: Vec<FindingGroup>,
}

pub fn build_crawl_report(
    options: &CrawlOptions,
    totals: &CrawlTotals,
    repos: &[CrawledRepo],
) -> CrawlReport {
    CrawlReport {
        schema_version: 2,
        tool_version: env!("CARGO_PKG_VERSION"),
        mode: "crawl",
        query: options
            .query
            .as_ref()
            .map(|query| query.trim().to_string())
            .filter(|query| !query.is_empty()),
        depth: options.depth,
        concurrency: options.concurrency,
        verify: options.verify,
        filters: CrawlFiltersReport {
            min_stars: options.filters.min_stars,
            max_size_kb: options.filters.max_size_kb,
            language: options.filters.language.clone(),
            include_forks: options.filters.include_forks,
            include_archived: options.filters.include_archived,
            pushed_days: options.filters.pushed_days,
        },
        discovered: totals.discovered,
        scanned: totals.scanned,
        failed: totals.failed,
        skipped: totals.skipped,
        skipped_known: totals.skipped_known,
        repos_with_leaks: totals.repos_with_leaks,
        unique_findings: repos.iter().map(|repo| repo.groups.len()).sum(),
        failing_findings: repos.iter().map(|repo| repo.failing_findings).sum(),
        verified_findings: repos
            .iter()
            .flat_map(|repo| repo.groups.iter())
            .filter(|group| {
                use crate::verify::VerificationStatus;
                group
                    .verification
                    .as_ref()
                    .map(|verification| verification.status == VerificationStatus::Verified)
                    .unwrap_or(false)
            })
            .count(),
        duration_ms: totals.duration.as_millis(),
        repos: repos
            .iter()
            .map(|repo| CrawlRepoReport {
                repo_name: repo.repo_name.clone(),
                clone_url: repo.clone_url.clone(),
                duration_ms: repo.duration_ms,
                unique_findings: repo.groups.len(),
                failing_findings: repo.failing_findings,
                findings: repo.findings.clone(),
                groups: repo.groups.clone(),
            })
            .collect(),
    }
}

pub fn crawl_report_json(
    options: &CrawlOptions,
    totals: &CrawlTotals,
    repos: &[CrawledRepo],
) -> String {
    serde_json::to_string_pretty(&build_crawl_report(options, totals, repos))
        .unwrap_or_else(|_| "{}".to_string())
}
