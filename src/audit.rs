use crate::git::GitCommitDiff;
use crate::scanner::{Finding, Scanner};
use crate::verify::verify_findings;
use rayon::prelude::*;

pub fn scan_commits(
    commits: &[GitCommitDiff],
    scanner: &Scanner,
    on_commit: &(dyn Fn() + Send + Sync),
) -> Vec<Finding> {
    let mut findings: Vec<Finding> = commits
        .par_iter()
        .flat_map(|commit| {
            let mut commit_findings = Vec::new();
            let lines = &commit.added_lines;
            let mut start = 0;

            while start < lines.len() {
                let file_path = &lines[start].file_path;
                let mut end = start + 1;

                while end < lines.len() && &lines[end].file_path == file_path {
                    end += 1;
                }

                let segment: Vec<(usize, &str)> = lines[start..end]
                    .iter()
                    .map(|line| (line.line_number, line.content.as_str()))
                    .collect();

                commit_findings.extend(scanner.scan_file_lines(
                    &segment,
                    file_path,
                    &commit.commit_id,
                    &commit.author,
                    &commit.date,
                ));

                start = end;
            }

            on_commit();
            commit_findings
        })
        .collect();

    if scanner.verify_online {
        verify_findings(&mut findings);
    }

    findings
}

pub fn scan_commits_quiet(commits: &[GitCommitDiff], scanner: &Scanner) -> Vec<Finding> {
    scan_commits(commits, scanner, &|| {})
}
