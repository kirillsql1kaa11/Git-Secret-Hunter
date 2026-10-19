use clap::Parser;
use colored::Colorize;
use git_secret_hunter::audit;
use git_secret_hunter::cli::{Cli, OutputFormat};
use git_secret_hunter::crawler::{CrawlFilters, CrawlerRunner, CrawlSeen, GitHubClient};
use git_secret_hunter::git::{CollectLimits, CollectScope, GitEngine};
use git_secret_hunter::incremental::{ScanMarkers, incremental_range, record_head};
use git_secret_hunter::reporter;
use git_secret_hunter::scanner::{Scanner, group_findings};
use git_secret_hunter::tui::launch_tui;
use git_secret_hunter::verify::VerificationStatus;
use indicatif::{ProgressBar, ProgressStyle};
use std::time::Instant;

fn main() {
    let args = Cli::parse();
    let start_time = Instant::now();

    let scanner = Scanner::new(
        args.ai_only,
        !args.no_entropy,
        args.entropy_threshold,
        args.min_entropy_len,
    )
    .with_verification(args.verify);

    if args.crawl {
        run_crawler(&args, &scanner);
        return;
    }

    let limits = CollectLimits {
        max_line_len: args.max_line_len,
        max_file_size: args.max_file_size,
    };

    let mut scope = CollectScope {
        since: args.since.clone(),
        until: args.until.clone(),
        rev_range: args.rev_range.clone(),
        include_submodules: args.submodules,
        include_notes: args.notes,
        include_lfs: args.lfs,
        allow_empty: false,
    };

    let mut markers = ScanMarkers::load();

    if args.incremental && !args.staged && scope.rev_range.is_none() {
        scope.rev_range = incremental_range(&args.path, &markers);
        scope.allow_empty = true;

        if args.format == OutputFormat::Text && !args.tui {
            match &scope.rev_range {
                Some(range) => println!("Incremental mode: scanning {}", range),
                None => println!(
                    "Incremental mode: no previous scan recorded for this repository, scanning full history"
                ),
            }
        }
    }

    let git_engine = GitEngine::new(
        &args.path,
        args.include_dangling,
        args.max_commits,
        limits,
    )
    .with_scope(scope);

    if args.format == OutputFormat::Text && !args.tui {
        reporter::console::print_banner();
    }

    let history = if args.staged {
        match git_engine.collect_staged() {
            Ok(history) => history,
            Err(e) => {
                eprintln!("Error collecting staged changes: {}", e);
                std::process::exit(2);
            }
        }
    } else {
        match git_engine.collect_all_commits() {
            Ok(history) => history,
            Err(e) => {
                eprintln!("Error collecting git history: {}", e);
                std::process::exit(2);
            }
        }
    };

    let total_commits = history.commits.len();
    let total_lines = history.total_lines();

    let progress_bar = if args.format == OutputFormat::Text && !args.tui {
        let bar = ProgressBar::new(total_commits as u64);
        bar.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} commits ({eta})")
                .unwrap()
                .progress_chars("#>-"),
        );
        Some(bar)
    } else {
        None
    };

    let findings = audit::scan_commits(&history.commits, &scanner, &|| {
        if let Some(ref bar) = progress_bar {
            bar.inc(1);
        }
    });

    if let Some(ref bar) = progress_bar {
        bar.finish_and_clear();
    }

    if args.incremental && !args.staged {
        record_head(&args.path, &mut markers);
    }

    let duration = start_time.elapsed();
    let groups = group_findings(&findings);
    let failing = groups.iter().any(|group| group.is_failing());

    if args.tui {
        if let Err(e) = launch_tui(groups) {
            eprintln!("Error launching TUI: {}", e);
        }
    } else {
        match args.format {
            OutputFormat::Text => {
                reporter::console::print_findings(&groups);
                reporter::console::print_summary(
                    &groups,
                    findings.len(),
                    total_commits,
                    total_lines,
                    history.skipped_lines,
                    history.skipped_files,
                    duration,
                );

                if args.verify {
                    let verified = count_status(&groups, VerificationStatus::Verified);
                    let invalid = count_status(&groups, VerificationStatus::Invalid);

                    println!(
                        "  {} {} live key(s), {} revoked/invalid",
                        "Verification:".bright_black(),
                        verified,
                        invalid
                    );
                }
            }
            OutputFormat::Json => {
                reporter::json::print_json(
                    &findings,
                    &groups,
                    &args.path.display().to_string(),
                    total_commits,
                    total_lines,
                    history.skipped_lines,
                    history.skipped_files,
                    duration,
                );
            }
        }
    }

    if failing {
        std::process::exit(1);
    }
}

fn count_status(
    groups: &[git_secret_hunter::scanner::FindingGroup],
    status: VerificationStatus,
) -> usize {
    groups
        .iter()
        .filter(|group| {
            group
                .verification
                .as_ref()
                .map(|verification| verification.status == status)
                .unwrap_or(false)
        })
        .count()
}

fn run_crawler(args: &Cli, scanner: &Scanner) {
    if args.format == OutputFormat::Text && !args.tui {
        println!(
            "Initializing GitHub repository recon (target limit: {}, concurrency: {})...",
            args.crawl_limit, args.crawl_concurrency
        );
    }

    let gh_client = match GitHubClient::new(args.github_token.as_deref()) {
        Ok(client) => client,
        Err(e) => {
            eprintln!("Error initializing GitHub client: {}", e);
            std::process::exit(2);
        }
    };

    let mut filters = CrawlFilters::default();

    if args.min_stars > 0 {
        filters.min_stars = args.min_stars;
    }

    if let Some(megabytes) = args.max_size_mb {
        filters.max_size_kb = (megabytes > 0).then(|| megabytes * 1024);
    }

    if let Some(language) = &args.language {
        if !language.trim().is_empty() {
            filters.language = Some(language.trim().to_string());
        }
    }

    filters.include_forks = args.include_forks;
    filters.include_archived = args.include_archived;
    filters.pushed_days = (args.pushed_days > 0).then_some(args.pushed_days);

    let mut seen = (!args.no_crawl_dedupe).then(CrawlSeen::load);
    let exclude = seen.as_ref().map(CrawlSeen::as_set).unwrap_or_default();

    let discovery = match gh_client.discover(args.query.as_deref(), args.crawl_limit, &filters, &exclude)
    {
        Ok(discovery) => discovery,
        Err(e) => {
            eprintln!("Error discovering GitHub repositories: {}", e);
            std::process::exit(2);
        }
    };

    if args.format == OutputFormat::Text && !args.tui {
        println!(
            "Discovered {} candidate repositories ({} skipped as filtered out or already scanned).\n",
            discovery.repos.len(),
            discovery.skipped
        );
    }

    let runner = CrawlerRunner::new(scanner, args.crawl_depth, args.crawl_concurrency);
    let stats = runner.run(&discovery.repos);

    if let Some(store) = seen.as_mut() {
        for repo in &discovery.repos {
            store.record(&repo.full_name);
        }

        store.save();
    }

    if args.tui {
        let mut all_findings = Vec::new();
        for repo in &stats.repo_summaries {
            all_findings.extend(repo.findings.clone());
        }

        if let Err(e) = launch_tui(group_findings(&all_findings)) {
            eprintln!("Error launching TUI: {}", e);
        }
    } else {
        match args.format {
            OutputFormat::Text => {
                stats.print_dashboard();

                if args.verify {
                    let mut verified = 0;

                    for repo in &stats.repo_summaries {
                        verified += repo
                            .findings
                            .iter()
                            .filter(|finding| {
                                finding
                                    .verification
                                    .as_ref()
                                    .map(|verification| {
                                        verification.status == VerificationStatus::Verified
                                    })
                                    .unwrap_or(false)
                            })
                            .count();
                    }

                    println!(
                        "  {} {} live key(s) confirmed by providers",
                        "Verification:".bright_black(),
                        verified
                    );
                }
            }
            OutputFormat::Json => {
                if let Ok(json) = serde_json::to_string_pretty(&stats) {
                    println!("{}", json);
                }
            }
        }
    }

    if stats.failing_findings > 0 {
        std::process::exit(1);
    }

    std::process::exit(0);
}
