#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use git_secret_hunter::crawler::CrawlFilters;
use git_secret_hunter::crawler::live::{
    CrawlEvent, CrawlOptions, CrawledRepo, build_crawl_report, run_crawl_blocking,
};
use git_secret_hunter::gui::launch as launch_gui;
use git_secret_hunter::gui::scan::{ScanOptions, run_scan};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::AtomicUsize;

#[derive(Clone, Default)]
struct GuiCli {
    path: Option<PathBuf>,
    out: Option<PathBuf>,
    selftest: bool,
    ai_only: bool,
    no_entropy: bool,
    staged: bool,
    no_dangling: bool,
    verify: bool,
    submodules: bool,
    notes: bool,
    lfs: bool,
    incremental: bool,
    since: Option<String>,
    until: Option<String>,
    rev_range: Option<String>,
    crawl: bool,
    query: Option<String>,
    crawl_limit: Option<usize>,
    crawl_depth: Option<usize>,
    crawl_concurrency: Option<usize>,
    github_token: Option<String>,
    min_stars: Option<u32>,
    max_size_mb: Option<u64>,
    language: Option<String>,
    pushed_days: Option<u32>,
    include_forks: bool,
    include_archived: bool,
    no_crawl_dedupe: bool,
}

impl GuiCli {
    fn parse() -> Self {
        let mut cli = Self::default();
        let mut args = std::env::args().skip(1);

        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--selftest" => cli.selftest = true,
                "--ai-only" => cli.ai_only = true,
                "--no-entropy" => cli.no_entropy = true,
                "--staged" => cli.staged = true,
                "--no-dangling" => cli.no_dangling = true,
                "--verify" => cli.verify = true,
                "--submodules" => cli.submodules = true,
                "--notes" => cli.notes = true,
                "--lfs" => cli.lfs = true,
                "--incremental" => cli.incremental = true,
                "--crawl" => cli.crawl = true,
                "--include-forks" => cli.include_forks = true,
                "--include-archived" => cli.include_archived = true,
                "--no-crawl-dedupe" => cli.no_crawl_dedupe = true,
                "-p" | "--path" => cli.path = args.next().map(PathBuf::from),
                "--out" => cli.out = args.next().map(PathBuf::from),
                "--query" => cli.query = args.next(),
                "--github-token" => cli.github_token = args.next(),
                "--language" => cli.language = args.next(),
                "--since" => cli.since = args.next(),
                "--until" => cli.until = args.next(),
                "--range" => cli.rev_range = args.next(),
                "--crawl-limit" => cli.crawl_limit = args.next().and_then(|value| value.parse().ok()),
                "--crawl-depth" => cli.crawl_depth = args.next().and_then(|value| value.parse().ok()),
                "--crawl-concurrency" => {
                    cli.crawl_concurrency = args.next().and_then(|value| value.parse().ok())
                }
                "--min-stars" => cli.min_stars = args.next().and_then(|value| value.parse().ok()),
                "--max-size-mb" => {
                    cli.max_size_mb = args.next().and_then(|value| value.parse().ok())
                }
                "--pushed-days" => {
                    cli.pushed_days = args.next().and_then(|value| value.parse().ok())
                }
                "-h" | "--help" => {
                    print_help();
                    std::process::exit(0);
                }
                _ => {}
            }
        }

        cli
    }

    fn to_scan_options(&self) -> ScanOptions {
        let mut options = ScanOptions::default();

        if let Some(path) = &self.path {
            options.path = path.clone();
        }

        options.ai_only = self.ai_only;
        options.check_entropy = !self.no_entropy;
        options.include_dangling = !self.no_dangling;
        options.staged = self.staged;
        options.verify = self.verify;
        options.include_submodules = self.submodules;
        options.include_notes = self.notes;
        options.include_lfs = self.lfs;
        options.incremental = self.incremental;
        options.since = self.since.clone();
        options.until = self.until.clone();
        options.rev_range = self.rev_range.clone();
        options
    }

    fn to_crawl_options(&self) -> CrawlOptions {
        let mut options = CrawlOptions::default();

        if let Some(limit) = self.crawl_limit {
            options.limit = limit;
        }

        if let Some(depth) = self.crawl_depth {
            options.depth = depth;
        }

        if let Some(concurrency) = self.crawl_concurrency {
            options.concurrency = concurrency;
        }

        if let Some(query) = &self.query {
            options.query = Some(query.clone());
        }

        if let Some(token) = &self.github_token {
            options.token = Some(token.clone());
        }

        options.ai_only = self.ai_only;
        options.verify = self.verify;
        options.skip_seen = !self.no_crawl_dedupe;
        options.remember_seen = !self.no_crawl_dedupe;

        let mut filters = CrawlFilters::default();

        if let Some(min_stars) = self.min_stars {
            filters.min_stars = min_stars;
        }

        if let Some(megabytes) = self.max_size_mb {
            filters.max_size_kb = (megabytes > 0).then(|| megabytes * 1024);
        }

        if let Some(language) = &self.language {
            if !language.trim().is_empty() {
                filters.language = Some(language.trim().to_string());
            }
        }

        filters.include_forks = self.include_forks;
        filters.include_archived = self.include_archived;
        filters.pushed_days = self.pushed_days.filter(|days| *days > 0);
        options.filters = filters;

        options
    }
}

fn print_help() {
    println!(
        "git-secret-hunter-gui [--path <REPO>] [--selftest] [--out <FILE>] [--ai-only] [--no-entropy] [--no-dangling] [--staged]\n\
         \n\
         git-secret-hunter-gui --selftest --crawl [--query <Q>] [--crawl-limit <N>] [--crawl-depth <N>] [--crawl-concurrency <N>] [--github-token <T>] [--out <FILE>]\n\
         \n\
         Scan options: [--verify] [--submodules] [--notes] [--lfs] [--incremental] [--since <DATE>] [--until <DATE>] [--range <REV..REV>]\n\
         Crawl filters: [--min-stars <N>] [--max-size-mb <MB>] [--language <LANG>] [--pushed-days <N>] [--include-forks] [--include-archived] [--no-crawl-dedupe]\n\
         \n\
         Without --selftest the graphical window is opened.\n\
         With --selftest the scan (or crawl, if --crawl is given) runs headlessly and the JSON report is written to --out (or printed to stdout)."
    );
}

fn main() {
    let cli = GuiCli::parse();

    if cli.selftest {
        std::process::exit(run_selftest(&cli));
    }

    if let Err(error) = launch_gui(cli.path.clone(), None) {
        eprintln!("Не удалось запустить GUI: {}", error);
        std::process::exit(2);
    }
}

fn write_or_print(cli: &GuiCli, json: &str) -> bool {
    match &cli.out {
        Some(out) => {
            if std::fs::write(out, json).is_err() {
                eprintln!("Не удалось записать отчёт: {}", out.display());
                return false;
            }

            true
        }
        None => {
            println!("{}", json);
            true
        }
    }
}

fn run_selftest(cli: &GuiCli) -> i32 {
    if cli.crawl {
        return run_crawl_selftest(cli);
    }

    let options = cli.to_scan_options();
    let progress = Arc::new(AtomicUsize::new(0));
    let total = Arc::new(AtomicUsize::new(0));

    match run_scan(&options, &progress, &total) {
        Ok(result) => {
            if !write_or_print(cli, &result.to_json()) {
                return 2;
            }

            if result.failing_groups() > 0 { 1 } else { 0 }
        }
        Err(error) => {
            if cli.out.is_some() {
                let escaped = error.replace('"', "'");
                let _ = write_or_print(cli, &format!("{{\"error\": \"{}\"}}", escaped));
            } else {
                eprintln!("{}", error);
            }

            2
        }
    }
}

fn run_crawl_selftest(cli: &GuiCli) -> i32 {
    let options = cli.to_crawl_options();
    let repos: Mutex<Vec<CrawledRepo>> = Mutex::new(Vec::new());

    let result = run_crawl_blocking(&options, &|event| {
        if let CrawlEvent::Scanned(repo) = event {
            if let Ok(mut repos) = repos.lock() {
                repos.push(*repo);
            }
        }
    });

    match result {
        Ok(totals) => {
            let repos = repos.lock().map(|repos| repos.clone()).unwrap_or_default();
            let report = build_crawl_report(&options, &totals, &repos);
            let json = serde_json::to_string_pretty(&report).unwrap_or_else(|_| "{}".to_string());

            if !write_or_print(cli, &json) {
                return 2;
            }

            if report.failing_findings > 0 { 1 } else { 0 }
        }
        Err(error) => {
            if cli.out.is_some() {
                let escaped = error.replace('"', "'");
                let _ = write_or_print(cli, &format!("{{\"error\": \"{}\"}}", escaped));
            } else {
                eprintln!("{}", error);
            }

            2
        }
    }
}
