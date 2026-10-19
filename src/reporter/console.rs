use crate::scanner::rules::Severity;
use crate::scanner::FindingGroup;
use colored::*;
use std::time::Duration;

const MAX_OCCURRENCES_SHOWN: usize = 5;

pub fn print_banner() {
    let title = format!(
        "   GIT SECRET HUNTER & AI KEY AUDITOR [v{}]",
        env!("CARGO_PKG_VERSION")
    );

    println!(
        "{}",
        "============================================================"
            .bright_cyan()
            .bold()
    );
    println!("{}", format!("{:<60}", title).bright_yellow().bold());
    println!(
        "{}",
        "   High-Speed Parallel History & Reflog Secret Scanner      "
            .white()
    );
    println!(
        "{}",
        "============================================================"
            .bright_cyan()
            .bold()
    );
}

pub fn severity_badge(severity: Severity) -> ColoredString {
    match severity {
        Severity::Critical => format!("[ {} ]", severity.label()).black().on_red().bold(),
        Severity::High => format!("[ {} ]", severity.label()).black().on_yellow().bold(),
        Severity::Medium => format!("[ {} ]", severity.label()).white().on_blue().bold(),
        Severity::Low => format!("[ {} ]", severity.label()).white().on_bright_black().bold(),
        Severity::Info => format!("[ {} ]", severity.label()).black().on_cyan().bold(),
    }
}

pub fn print_findings(groups: &[FindingGroup]) {
    for (idx, group) in groups.iter().enumerate() {
        println!(
            "\n{} #{}: {} - {} (Confidence: {})",
            severity_badge(group.severity),
            idx + 1,
            group.rule_name.bright_white().bold(),
            group.category.label().bright_cyan(),
            match group.confidence.as_str() {
                "HIGH" => group.confidence.bright_green().bold(),
                "LOW" => group.confidence.bright_black(),
                _ => group.confidence.normal(),
            }
        );

        let files = group.files();
        let locations = if files.len() == 1 {
            format!("{}:{}", files[0], group.occurrences[0].line_number)
        } else {
            format!("{} files", files.len())
        };

        println!(
            "  {} {}",
            "Location:  ".bright_black(),
            locations.bright_white()
        );

        println!(
            "  {} {} commit(s), first {}, last {}",
            "History:   ".bright_black(),
            group.commit_count.to_string().yellow(),
            group.first_seen.bright_black(),
            group.last_seen.bright_black()
        );

        println!(
            "  {} {}",
            "Preview:   ".bright_black(),
            group.secret_preview.bright_red().bold()
        );

        println!(
            "  {} {}{}",
            "Fingerprint:".bright_black(),
            group.fingerprint.bright_blue(),
            if group.family.is_empty() {
                String::new()
            } else {
                format!(" ({})", group.family)
            }
            .bright_black()
        );

        if let Some(entropy) = group.entropy {
            println!("  {} {:.2} bits", "Entropy:   ".bright_black(), entropy);
        }

        for occurrence in group.occurrences.iter().take(MAX_OCCURRENCES_SHOWN) {
            println!(
                "      {} {} {}:{}",
                occurrence
                    .commit_id
                    .get(..10)
                    .unwrap_or(occurrence.commit_id.as_str())
                    .bright_magenta(),
                occurrence.commit_author.cyan(),
                occurrence.file_path.bright_white(),
                occurrence.line_number.to_string().yellow()
            );
        }

        if group.occurrences.len() > MAX_OCCURRENCES_SHOWN {
            println!(
                "      {}",
                format!(
                    "... and {} more occurrence(s)",
                    group.occurrences.len() - MAX_OCCURRENCES_SHOWN
                )
                .bright_black()
            );
        }
    }
}

pub fn print_summary(
    groups: &[FindingGroup],
    total_findings: usize,
    commits_scanned: usize,
    lines_scanned: usize,
    skipped_lines: usize,
    skipped_files: usize,
    duration: Duration,
) {
    println!(
        "\n{}",
        "------------------------------------------------------------".bright_black()
    );
    println!("{}", "SCAN SUMMARY".bright_white().bold());
    println!("  Commits Scanned:     {}", commits_scanned.to_string().cyan());
    println!("  Diff Lines Checked:  {}", lines_scanned.to_string().cyan());

    if skipped_lines > 0 || skipped_files > 0 {
        println!(
            "  Skipped By Limits:   {} line(s) in {} file(s)",
            skipped_lines.to_string().yellow(),
            skipped_files.to_string().yellow()
        );
    }

    println!("  Scan Duration:       {:.2?}", duration);

    let count = |severity: Severity| {
        groups
            .iter()
            .filter(|group| group.severity == severity)
            .count()
    };

    let critical = count(Severity::Critical);
    let high = count(Severity::High);
    let medium = count(Severity::Medium);
    let low = count(Severity::Low);
    let info = count(Severity::Info);

    println!(
        "  Unique Secrets:      {} ({} occurrence(s))",
        groups.len().to_string().bold(),
        total_findings.to_string().cyan()
    );
    println!(
        "  By Severity:         Critical: {}, High: {}, Medium: {}, Low: {}, Info: {}",
        critical.to_string().red().bold(),
        high.to_string().yellow().bold(),
        medium.to_string().blue(),
        low.to_string().bright_black(),
        info.to_string().cyan()
    );

    println!(
        "{}",
        "------------------------------------------------------------".bright_black()
    );

    let failing = groups.iter().filter(|group| group.is_failing()).count();

    if groups.is_empty() {
        println!(
            "{}",
            "SUCCESS: No leaked secrets or AI keys detected!"
                .bright_green()
                .bold()
        );
    } else if failing == 0 {
        println!(
            "{}",
            "INFO: only non-blocking findings (public or test credentials) were detected."
                .cyan()
                .bold()
        );
    } else {
        println!(
            "{}",
            format!(
                "SECURITY ALERT: Found {} exposed secret(s) in git history!",
                failing
            )
            .bright_red()
            .bold()
        );
    }
}
