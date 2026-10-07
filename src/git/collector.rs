use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

#[derive(Debug, Clone)]
pub struct DiffLine {
    pub file_path: String,
    pub line_number: usize,
    pub content: String,
}

#[derive(Debug, Clone)]
pub struct GitCommitDiff {
    pub commit_id: String,
    pub author: String,
    pub date: String,
    pub message: String,
    pub added_lines: Vec<DiffLine>,
}

pub struct GitEngine {
    repo_path: PathBuf,
    include_dangling: bool,
    max_commits: Option<usize>,
}

impl GitEngine {
    pub fn new<P: AsRef<Path>>(
        repo_path: P,
        include_dangling: bool,
        max_commits: Option<usize>,
    ) -> Self {
        Self {
            repo_path: repo_path.as_ref().to_path_buf(),
            include_dangling,
            max_commits,
        }
    }

    pub fn collect_staged(&self) -> Result<GitCommitDiff, String> {
        let output = Command::new("git")
            .args(["diff", "--cached", "-U0"])
            .current_dir(&self.repo_path)
            .output()
            .map_err(|e| format!("Failed to run git diff --cached: {}", e))?;

        if !output.status.success() {
            return Err(String::from_utf8_lossy(&output.stderr).to_string());
        }

        let reader = BufReader::new(&output.stdout[..]);
        let mut added_lines = Vec::new();
        let mut current_file = String::new();
        let mut current_line_num = 1usize;

        for line_res in reader.lines() {
            let line = line_res.unwrap_or_default();

            if line.starts_with("diff --git ") {
                if let Some(pos) = line.rfind(" b/") {
                    current_file = line[pos + 3..].to_string();
                }
            } else if line.starts_with("@@ ") {
                if let Some(plus_pos) = line.find('+') {
                    let rest = &line[plus_pos + 1..];
                    let num_str: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
                    if let Ok(n) = num_str.parse::<usize>() {
                        current_line_num = n;
                    }
                }
            } else if line.starts_with('+') && !line.starts_with("+++ ") {
                let content = line[1..].to_string();
                added_lines.push(DiffLine {
                    file_path: current_file.clone(),
                    line_number: current_line_num,
                    content,
                });
                current_line_num += 1;
            }
        }

        Ok(GitCommitDiff {
            commit_id: "STAGED_INDEX".to_string(),
            author: "Local Worktree".to_string(),
            date: "Uncommitted".to_string(),
            message: "Staged Changes (Pre-commit)".to_string(),
            added_lines,
        })
    }

    pub fn collect_all_commits(&self) -> Result<Vec<GitCommitDiff>, String> {
        let mut args = vec![
            "log",
            "--all",
            "--reflog",
            "--full-history",
            "--date=iso",
            "--format=COMMIT_META%x09%H%x09%an%x09%ad%x09%s",
            "-p",
            "-U0",
        ];

        let limit_str;
        if let Some(max) = self.max_commits {
            limit_str = format!("-n{}", max);
            args.push(&limit_str);
        }

        let mut child = Command::new("git")
            .args(&args)
            .current_dir(&self.repo_path)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("Failed to spawn git log: {}", e))?;

        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| "Failed to capture git stdout".to_string())?;

        let reader = BufReader::with_capacity(1024 * 1024, stdout);
        let mut commits = Vec::new();

        let mut current_commit: Option<GitCommitDiff> = None;
        let mut current_file = String::new();
        let mut current_line_num = 1usize;
        let mut visited_shas = std::collections::HashSet::new();

        for line_res in reader.lines() {
            let line = match line_res {
                Ok(l) => l,
                Err(_) => continue,
            };

            if line.starts_with("COMMIT_META\t") {
                if let Some(c) = current_commit.take() {
                    commits.push(c);
                }

                let parts: Vec<&str> = line.split('\t').collect();
                let commit_id = parts.get(1).unwrap_or(&"unknown").to_string();
                let author = parts.get(2).unwrap_or(&"unknown").to_string();
                let date = parts.get(3).unwrap_or(&"unknown").to_string();
                let message = parts.get(4).unwrap_or(&"").to_string();

                visited_shas.insert(commit_id.clone());

                current_commit = Some(GitCommitDiff {
                    commit_id,
                    author,
                    date,
                    message,
                    added_lines: Vec::new(),
                });
                current_file.clear();
            } else if line.starts_with("diff --git ") {
                if let Some(pos) = line.rfind(" b/") {
                    current_file = line[pos + 3..].to_string();
                }
            } else if line.starts_with("@@ ") {
                if let Some(plus_pos) = line.find('+') {
                    let rest = &line[plus_pos + 1..];
                    let num_str: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
                    if let Ok(n) = num_str.parse::<usize>() {
                        current_line_num = n;
                    }
                }
            } else if line.starts_with('+') && !line.starts_with("+++ ") {
                if let Some(ref mut c) = current_commit {
                    let content = line[1..].to_string();
                    c.added_lines.push(DiffLine {
                        file_path: current_file.clone(),
                        line_number: current_line_num,
                        content,
                    });
                }
                current_line_num += 1;
            }
        }

        if let Some(c) = current_commit {
            commits.push(c);
        }

        let _ = child.wait();

        if self.include_dangling {
            let dangling = self.find_dangling_commits();
            for sha in dangling {
                if visited_shas.contains(&sha) {
                    continue;
                }
                if let Ok(d_commit) = self.collect_single_commit(&sha) {
                    commits.push(d_commit);
                }
            }
        }

        Ok(commits)
    }

    fn find_dangling_commits(&self) -> Vec<String> {
        let output = match Command::new("git")
            .args(["fsck", "--lost-found", "--unreachable"])
            .current_dir(&self.repo_path)
            .output()
        {
            Ok(o) => o,
            Err(_) => return Vec::new(),
        };

        let mut shas = Vec::new();
        let reader = BufReader::new(&output.stdout[..]);

        for line_res in reader.lines() {
            let line = line_res.unwrap_or_default();
            if line.contains("commit ") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 3 {
                    shas.push(parts[2].to_string());
                }
            }
        }

        shas
    }

    fn collect_single_commit(&self, sha: &str) -> Result<GitCommitDiff, String> {
        let output = Command::new("git")
            .args([
                "log",
                "-1",
                "--date=iso",
                "--format=COMMIT_META%x09%H%x09%an%x09%ad%x09%s",
                "-p",
                "-U0",
                sha,
            ])
            .current_dir(&self.repo_path)
            .output()
            .map_err(|e| format!("Failed to read commit {}: {}", sha, e))?;

        let reader = BufReader::new(&output.stdout[..]);
        let mut commit_diff = GitCommitDiff {
            commit_id: sha.to_string(),
            author: "Dangling Commit".to_string(),
            date: "Unknown".to_string(),
            message: "Unreferenced / Dangling".to_string(),
            added_lines: Vec::new(),
        };

        let mut current_file = String::new();
        let mut current_line_num = 1usize;

        for line_res in reader.lines() {
            let line = line_res.unwrap_or_default();

            if line.starts_with("COMMIT_META\t") {
                let parts: Vec<&str> = line.split('\t').collect();
                if parts.len() >= 5 {
                    commit_diff.commit_id = parts[1].to_string();
                    commit_diff.author = parts[2].to_string();
                    commit_diff.date = parts[3].to_string();
                    commit_diff.message = parts[4].to_string();
                }
            } else if line.starts_with("diff --git ") {
                if let Some(pos) = line.rfind(" b/") {
                    current_file = line[pos + 3..].to_string();
                }
            } else if line.starts_with("@@ ") {
                if let Some(plus_pos) = line.find('+') {
                    let rest = &line[plus_pos + 1..];
                    let num_str: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
                    if let Ok(n) = num_str.parse::<usize>() {
                        current_line_num = n;
                    }
                }
            } else if line.starts_with('+') && !line.starts_with("+++ ") {
                let content = line[1..].to_string();
                commit_diff.added_lines.push(DiffLine {
                    file_path: current_file.clone(),
                    line_number: current_line_num,
                    content,
                });
                current_line_num += 1;
            }
        }

        Ok(commit_diff)
    }
}
