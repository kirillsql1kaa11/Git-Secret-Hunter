use crate::scanner::rules::Severity;
use crate::scanner::Finding;
use colored::*;
use std::time::Duration;

pub fn print_banner() {
    println!(
        "{}",
        "============================================================"
            .bright_cyan()
            .bold()
    );
    println!(
        "{}",
        "   GIT SECRET HUNTER & AI KEY AUDITOR [v0.1.0]              "
            .bright_yellow()
            .bold()
    );
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

pub fn print_findings(findings: &[Finding]) {
    for (idx, f) in findings.iter().enumerate() {
        let badge = match f.severity {
            Severity::Critical => format!("[ {} ]", f.severity.label()).black().on_red().bold(),
            Severity::High => format!("[ {} ]", f.severity.label())
                .black()
                .on_yellow()
                .bold(),
            Severity::Medium => format!("[ {} ]", f.severity.label())
                .white()
                .on_blue()
                .bold(),
            Severity::Low => format!("[ {} ]", f.severity.label())
                .white()
                .on_bright_black()
                .bold(),
        };

        println!(
            "\n{} #{}: {} - {} (Confidence: {})",
            badge,
            idx + 1,
            f.rule_name.bright_white().bold(),
            f.category.label().bright_cyan(),
            match f.confidence.as_str() {
                "HIGH" => f.confidence.bright_green().bold(),
                "LOW" => f.confidence.bright_black(),
                _ => f.confidence.normal(),
            }
        );

        println!(
            "  {} {}:{}",
            "Location:  ".bright_black(),
            f.file_path.bright_white(),
            f.line_number.to_string().yellow()
        );

        println!(
            "  {} {} ({})",
            "Commit:    ".bright_black(),
            &f.commit_id[..f.commit_id.len().min(10)].bright_magenta(),
            f.commit_author.cyan()
        );

        println!(
            "  {} {}",
            "Date:      ".bright_black(),
            f.commit_date.bright_black()
        );

        println!(
            "  {} {}",
            "Preview:   ".bright_black(),
            f.secret_preview.bright_red().bold()
        );

        if let Some(ent) = f.entropy {
            println!(
                "  {} {:.2} bits",
                "Entropy:   ".bright_black(),
                ent
            );
        }
    }
}

pub fn print_summary(
    findings: &[Finding],
    commits_scanned: usize,
    lines_scanned: usize,
    duration: Duration,
) {
    println!(
        "\n{}",
        "------------------------------------------------------------"
            .bright_black()
    );
    println!("{}", "SCAN SUMMARY".bright_white().bold());
    println!("  Commits Scanned:     {}", commits_scanned.to_string().cyan());
    println!("  Diff Lines Checked:  {}", lines_scanned.to_string().cyan());
    println!("  Scan Duration:       {:.2?}", duration);

    let critical_count = findings
        .iter()
        .filter(|f| f.severity == Severity::Critical)
        .count();
    let high_count = findings
        .iter()
        .filter(|f| f.severity == Severity::High)
        .count();
    let medium_count = findings
        .iter()
        .filter(|f| f.severity == Severity::Medium)
        .count();
    let low_count = findings
        .iter()
        .filter(|f| f.severity == Severity::Low)
        .count();

    println!(
        "  Findings:            {} (Critical: {}, High: {}, Medium: {}, Low: {})",
        findings.len().to_string().bold(),
        critical_count.to_string().red().bold(),
        high_count.to_string().yellow().bold(),
        medium_count.to_string().blue(),
        low_count.to_string().bright_black()
    );

    println!(
        "{}",
        "------------------------------------------------------------"
            .bright_black()
    );

    if findings.is_empty() {
        println!(
            "{}",
            "SUCCESS: No leaked secrets or AI keys detected!"
                .bright_green()
                .bold()
        );
    } else {
        println!(
            "{}",
            format!(
                "SECURITY ALERT: Found {} exposed secret(s) in git history!",
                findings.len()
            )
            .bright_red()
            .bold()
        );
    }
}
