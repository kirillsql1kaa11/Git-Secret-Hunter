use clap::Parser;
use git_secret_hunter::cli::{Cli, OutputFormat};
use git_secret_hunter::crawler::{CrawlerRunner, GitHubClient};
use git_secret_hunter::git::{CollectLimits, GitEngine};
use git_secret_hunter::reporter;
use git_secret_hunter::scanner::{group_findings, Finding, Scanner};
use git_secret_hunter::tui::launch_tui;
use indicatif::{ProgressBar, ProgressStyle};
use rayon::prelude::*;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

fn main() {
    let args = Cli::parse();
    let start_time = Instant::now();

    let scanner = Scanner::new(
        args.ai_only,
        !args.no_entropy,
        args.entropy_threshold,
        args.min_entropy_len,
    );

    if args.crawl {
        run_crawler(&args, &scanner);
        return;
    }

    let limits = CollectLimits {
        max_line_len: args.max_line_len,
        max_file_size: args.max_file_size,
    };

    let git_engine = GitEngine::new(
        &args.path,
        args.include_dangling,
        args.max_commits,
        limits,
    );

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
    let lines_counter = AtomicUsize::new(0);

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

    let findings: Vec<Finding> = history
        .commits
        .par_iter()
        .flat_map(|commit| {
            let mut commit_findings = Vec::new();
            lines_counter.fetch_add(commit.added_lines.len(), Ordering::Relaxed);

            for diff_line in &commit.added_lines {
                let found = scanner.scan_line(
                    &diff_line.content,
                    &diff_line.file_path,
                    diff_line.line_number,
                    &commit.commit_id,
                    &commit.author,
                    &commit.date,
                );
                commit_findings.extend(found);
            }

            if let Some(ref bar) = progress_bar {
                bar.inc(1);
            }

            commit_findings
        })
        .collect();

    if let Some(ref bar) = progress_bar {
        bar.finish_and_clear();
    }

    let duration = start_time.elapsed();
    let total_lines = lines_counter.load(Ordering::Relaxed);
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

    let repos = if let Some(ref query) = args.query {
        match gh_client.search_repos(query, args.crawl_limit) {
            Ok(repos) => repos,
            Err(e) => {
                eprintln!("Error querying GitHub repositories: {}", e);
                std::process::exit(2);
            }
        }
    } else {
        match gh_client.fetch_random_repos(args.crawl_limit) {
            Ok(repos) => repos,
            Err(e) => {
                eprintln!("Error fetching random GitHub repositories: {}", e);
                std::process::exit(2);
            }
        }
    };

    if args.format == OutputFormat::Text && !args.tui {
        println!(
            "Discovered {} candidate repositories. Starting mass audit...\n",
            repos.len()
        );
    }

    let runner = CrawlerRunner::new(scanner, args.crawl_depth, args.crawl_concurrency);
    let stats = runner.run(&repos);

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
            OutputFormat::Text => stats.print_dashboard(),
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
