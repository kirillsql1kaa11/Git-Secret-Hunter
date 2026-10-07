use clap::Parser;
use git_secret_hunter::cli::{Cli, OutputFormat};
use git_secret_hunter::crawler::{CrawlerRunner, GitHubClient};
use git_secret_hunter::git::GitEngine;
use git_secret_hunter::reporter;
use git_secret_hunter::scanner::{Finding, Scanner};
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
        if args.format == OutputFormat::Text && !args.tui {
            println!("Initializing GitHub repository recon (target limit: {})...", args.crawl_limit);
        }

        let gh_client = match GitHubClient::new(args.github_token.as_deref()) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("Error initializing GitHub client: {}", e);
                std::process::exit(1);
            }
        };

        let repos = if let Some(ref q) = args.query {
            match gh_client.search_repos(q, args.crawl_limit) {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("Error querying GitHub repositories: {}", e);
                    std::process::exit(1);
                }
            }
        } else {
            match gh_client.fetch_random_repos(args.crawl_limit) {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("Error fetching random GitHub repositories: {}", e);
                    std::process::exit(1);
                }
            }
        };

        if args.format == OutputFormat::Text && !args.tui {
            println!("Discovered {} candidate repositories. Starting mass audit...\n", repos.len());
        }

        let runner = CrawlerRunner::new(&scanner, args.crawl_depth);
        let stats = runner.run(&repos);

        if args.tui {
            let mut all_findings = Vec::new();
            for repo in &stats.repo_summaries {
                all_findings.extend(repo.findings.clone());
            }
            if let Err(e) = launch_tui(all_findings) {
                eprintln!("Error launching TUI: {}", e);
            }
        } else {
            match args.format {
                OutputFormat::Text => {
                    stats.print_dashboard();
                }
                OutputFormat::Json => {
                    if let Ok(json) = serde_json::to_string_pretty(&stats) {
                        println!("{}", json);
                    }
                }
            }
        }

        if stats.total_findings > 0 {
            std::process::exit(1);
        } else {
            std::process::exit(0);
        }
    }

    let git_engine = GitEngine::new(
        &args.path,
        args.include_dangling,
        args.max_commits,
    );

    if args.format == OutputFormat::Text && !args.tui {
        reporter::console::print_banner();
    }

    let commits = if args.staged {
        match git_engine.collect_staged() {
            Ok(c) => vec![c],
            Err(e) => {
                eprintln!("Error collecting staged changes: {}", e);
                std::process::exit(2);
            }
        }
    } else {
        match git_engine.collect_all_commits() {
            Ok(c) => c,
            Err(e) => {
                eprintln!("Error collecting git history: {}", e);
                std::process::exit(2);
            }
        }
    };

    let total_commits = commits.len();
    let lines_counter = AtomicUsize::new(0);

    let pb = if args.format == OutputFormat::Text && !args.tui {
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

    let findings: Vec<Finding> = commits
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

            if let Some(ref bar) = pb {
                bar.inc(1);
            }

            commit_findings
        })
        .collect();

    if let Some(ref bar) = pb {
        bar.finish_and_clear();
    }

    let duration = start_time.elapsed();
    let total_lines = lines_counter.load(Ordering::Relaxed);

    if args.tui {
        if let Err(e) = launch_tui(findings.clone()) {
            eprintln!("Error launching TUI: {}", e);
        }
    } else {
        match args.format {
            OutputFormat::Text => {
                reporter::console::print_findings(&findings);
                reporter::console::print_summary(
                    &findings,
                    total_commits,
                    total_lines,
                    duration,
                );
            }
            OutputFormat::Json => {
                reporter::json::print_json(findings.clone(), total_commits, total_lines, duration);
            }
        }
    }

    if !findings.is_empty() {
        std::process::exit(1);
    }
}
