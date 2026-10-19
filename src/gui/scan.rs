use crate::audit;
use crate::git::{CollectLimits, CollectScope, GitEngine};
use crate::incremental::{ScanMarkers, incremental_range, record_head};
use crate::reporter::json::{ReportMeta, build_report};
use crate::scanner::{Finding, FindingGroup, Scanner, group_findings};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct ScanOptions {
    pub path: PathBuf,
    pub ai_only: bool,
    pub check_entropy: bool,
    pub entropy_threshold: f64,
    pub min_entropy_len: usize,
    pub include_dangling: bool,
    pub staged: bool,
    pub max_commits: Option<usize>,
    pub max_line_len: usize,
    pub max_file_size: usize,
    pub verify: bool,
    pub include_submodules: bool,
    pub include_notes: bool,
    pub include_lfs: bool,
    pub incremental: bool,
    pub since: Option<String>,
    pub until: Option<String>,
    pub rev_range: Option<String>,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            path: std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
            ai_only: false,
            check_entropy: true,
            entropy_threshold: 4.5,
            min_entropy_len: 24,
            include_dangling: true,
            staged: false,
            max_commits: None,
            max_line_len: 8192,
            max_file_size: 8 * 1024 * 1024,
            verify: false,
            include_submodules: false,
            include_notes: false,
            include_lfs: false,
            incremental: false,
            since: None,
            until: None,
            rev_range: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ScanResult {
    pub repo_path: String,
    pub commits: usize,
    pub lines: usize,
    pub skipped_lines: usize,
    pub skipped_files: usize,
    pub duration: Duration,
    pub findings: Vec<Finding>,
    pub groups: Vec<FindingGroup>,
}

impl ScanResult {
    pub fn failing_groups(&self) -> usize {
        self.groups
            .iter()
            .filter(|group| group.is_failing())
            .count()
    }

    pub fn to_json(&self) -> String {
        let report = build_report(
            &self.findings,
            &self.groups,
            ReportMeta {
                repo_path: self.repo_path.clone(),
                commits_scanned: self.commits,
                lines_scanned: self.lines,
                skipped_lines: self.skipped_lines,
                skipped_files: self.skipped_files,
                duration: self.duration,
            },
        );

        serde_json::to_string_pretty(&report).unwrap_or_else(|_| "{}".to_string())
    }
}

pub enum ScanOutcome {
    Done(Box<ScanResult>),
    Failed(String),
}

pub struct ScanHandle {
    pub progress: Arc<AtomicUsize>,
    pub total: Arc<AtomicUsize>,
    pub path: String,
    pub started: Instant,
    receiver: Receiver<ScanOutcome>,
}

impl ScanHandle {
    pub fn poll(&self) -> Option<ScanOutcome> {
        self.receiver.try_recv().ok()
    }

    pub fn fraction(&self) -> f32 {
        let total = self.total.load(Ordering::Relaxed);
        if total == 0 {
            return 0.0;
        }

        (self.progress.load(Ordering::Relaxed) as f32 / total as f32).clamp(0.0, 1.0)
    }

    pub fn scanned_commits(&self) -> usize {
        self.progress.load(Ordering::Relaxed)
    }

    pub fn total_commits(&self) -> usize {
        self.total.load(Ordering::Relaxed)
    }
}

pub fn run_scan(
    options: &ScanOptions,
    progress: &Arc<AtomicUsize>,
    total: &Arc<AtomicUsize>,
) -> Result<ScanResult, String> {
    let started = Instant::now();

    let scanner = Scanner::new(
        options.ai_only,
        options.check_entropy,
        options.entropy_threshold,
        options.min_entropy_len,
    )
    .with_verification(options.verify);

    let limits = CollectLimits {
        max_line_len: options.max_line_len,
        max_file_size: options.max_file_size,
    };

    let mut scope = CollectScope {
        since: options.since.clone(),
        until: options.until.clone(),
        rev_range: options.rev_range.clone(),
        include_submodules: options.include_submodules,
        include_notes: options.include_notes,
        include_lfs: options.include_lfs,
        allow_empty: false,
    };

    let mut markers = ScanMarkers::load();

    if options.incremental && !options.staged && scope.rev_range.is_none() {
        scope.rev_range = incremental_range(&options.path, &markers);
        scope.allow_empty = true;
    }

    let engine = GitEngine::new(
        &options.path,
        options.include_dangling,
        options.max_commits,
        limits,
    )
    .with_scope(scope);

    let history = if options.staged {
        engine.collect_staged()?
    } else {
        engine.collect_all_commits()?
    };

    total.store(history.commits.len(), Ordering::Relaxed);

    let lines = history.total_lines();

    let findings = audit::scan_commits(&history.commits, &scanner, &|| {
        progress.fetch_add(1, Ordering::Relaxed);
    });

    if options.incremental && !options.staged {
        record_head(&options.path, &mut markers);
    }

    let groups = group_findings(&findings);

    Ok(ScanResult {
        repo_path: engine.repo_path().display().to_string(),
        commits: history.commits.len(),
        lines,
        skipped_lines: history.skipped_lines,
        skipped_files: history.skipped_files,
        duration: started.elapsed(),
        findings,
        groups,
    })
}

pub fn spawn_scan<F>(options: ScanOptions, notify: F) -> ScanHandle
where
    F: Fn() + Send + 'static,
{
    let progress = Arc::new(AtomicUsize::new(0));
    let total = Arc::new(AtomicUsize::new(0));
    let (sender, receiver): (Sender<ScanOutcome>, Receiver<ScanOutcome>) = channel();

    let handle = ScanHandle {
        progress: Arc::clone(&progress),
        total: Arc::clone(&total),
        path: options.path.display().to_string(),
        started: Instant::now(),
        receiver,
    };

    std::thread::spawn(move || {
        let outcome = match run_scan(&options, &progress, &total) {
            Ok(result) => ScanOutcome::Done(Box::new(result)),
            Err(error) => ScanOutcome::Failed(error),
        };

        let _ = sender.send(outcome);
        notify();
    });

    handle
}
