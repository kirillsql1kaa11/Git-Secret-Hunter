use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read};
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

#[derive(Debug, Clone)]
pub struct HistoryScan {
    pub commits: Vec<GitCommitDiff>,
    pub skipped_lines: usize,
    pub skipped_files: usize,
}

impl HistoryScan {
    pub fn total_lines(&self) -> usize {
        self.commits.iter().map(|c| c.added_lines.len()).sum()
    }
}

#[derive(Debug, Clone, Copy)]
pub struct CollectLimits {
    pub max_line_len: usize,
    pub max_file_size: usize,
}

impl Default for CollectLimits {
    fn default() -> Self {
        Self {
            max_line_len: 8192,
            max_file_size: 8 * 1024 * 1024,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct CollectScope {
    pub since: Option<String>,
    pub until: Option<String>,
    pub rev_range: Option<String>,
    pub include_submodules: bool,
    pub include_notes: bool,
    pub include_lfs: bool,
    pub allow_empty: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MergeDiffMode {
    FirstParent,
    AllParents,
}

pub struct GitEngine {
    repo_path: PathBuf,
    include_dangling: bool,
    max_commits: Option<usize>,
    limits: CollectLimits,
    scope: CollectScope,
}

impl GitEngine {
    pub fn new<P: AsRef<Path>>(
        repo_path: P,
        include_dangling: bool,
        max_commits: Option<usize>,
        limits: CollectLimits,
    ) -> Self {
        Self {
            repo_path: repo_path.as_ref().to_path_buf(),
            include_dangling,
            max_commits,
            limits,
            scope: CollectScope::default(),
        }
    }

    pub fn with_scope(mut self, scope: CollectScope) -> Self {
        self.scope = scope;
        self
    }

    pub fn repo_path(&self) -> &Path {
        &self.repo_path
    }

    fn git(&self) -> Command {
        let mut command = Command::new("git");
        command.current_dir(&self.repo_path);
        command
    }

    fn ensure_repository(&self) -> Result<(), String> {
        let output = self
            .git()
            .args(["rev-parse", "--is-inside-work-tree"])
            .output()
            .map_err(|e| {
                format!(
                    "Failed to run git in '{}': {}. Is git installed and on PATH?",
                    self.repo_path.display(),
                    e
                )
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let reason = stderr
                .lines()
                .find(|line| !line.trim().is_empty())
                .unwrap_or("not a git repository");
            return Err(format!(
                "'{}' is not a usable git repository: {}",
                self.repo_path.display(),
                reason.trim()
            ));
        }

        Ok(())
    }

    fn detect_merge_mode(&self) -> MergeDiffMode {
        let supported = self
            .git()
            .args(["log", "-1", "--diff-merges=first-parent", "--format=%H"])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);

        if supported {
            MergeDiffMode::FirstParent
        } else {
            MergeDiffMode::AllParents
        }
    }

    pub fn collect_staged(&self) -> Result<HistoryScan, String> {
        self.ensure_repository()?;

        let output = self
            .git()
            .args(["-c", "core.quotepath=false", "diff", "--cached", "-U0"])
            .output()
            .map_err(|e| format!("Failed to run git diff --cached: {}", e))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            return Err(format!(
                "git diff --cached failed in '{}': {}",
                self.repo_path.display(),
                stderr
            ));
        }

        let reader = BufReader::new(&output.stdout[..]);
        let mut parser = DiffParser::new(self.limits);
        let mut added_lines = Vec::new();

        for line_res in reader.lines() {
            let line = match line_res {
                Ok(l) => l,
                Err(_) => continue,
            };

            if line.starts_with("diff --git ") {
                parser.start_file(parse_diff_header(&line));
                continue;
            }

            parser.consume(&line, &mut added_lines);
        }

        let commit = GitCommitDiff {
            commit_id: "STAGED_INDEX".to_string(),
            author: "Local Worktree".to_string(),
            date: "Uncommitted".to_string(),
            message: "Staged Changes (Pre-commit)".to_string(),
            added_lines,
        };

        Ok(HistoryScan {
            commits: vec![commit],
            skipped_lines: parser.skipped_lines,
            skipped_files: parser.skipped_files,
        })
    }

    pub fn collect_all_commits(&self) -> Result<HistoryScan, String> {
        self.ensure_repository()?;

        let merge_mode = self.detect_merge_mode();
        let mut args: Vec<String> = vec!["-c".into(), "core.quotepath=false".into(), "log".into()];

        if let Some(range) = &self.scope.rev_range {
            if !range.trim().is_empty() {
                args.push(range.clone());
            } else {
                args.push("--all".into());
                args.push("--reflog".into());
            }
        } else {
            args.push("--all".into());
            args.push("--reflog".into());
        }

        args.push("--full-history".into());
        args.push("--date=iso".into());
        args.push("--format=COMMIT_META%x09%H%x09%an%x09%ad%x09%s".into());

        if let Some(since) = &self.scope.since {
            if !since.trim().is_empty() {
                args.push(format!("--since={}", since.trim()));
            }
        }

        if let Some(until) = &self.scope.until {
            if !until.trim().is_empty() {
                args.push(format!("--until={}", until.trim()));
            }
        }

        match merge_mode {
            MergeDiffMode::FirstParent => args.push("--diff-merges=first-parent".into()),
            MergeDiffMode::AllParents => args.push("-m".into()),
        }

        args.push("-p".into());
        args.push("-U0".into());

        if let Some(max) = self.max_commits {
            args.push(format!("-n{}", max));
        }

        let mut child = self
            .git()
            .args(&args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("Failed to spawn git log: {}", e))?;

        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| "Failed to capture git stdout".to_string())?;

        let stderr_reader = child.stderr.take().map(|mut handle| {
            std::thread::spawn(move || {
                let mut buffer = String::new();
                let _ = handle.read_to_string(&mut buffer);
                buffer
            })
        });

        let reader = BufReader::with_capacity(1024 * 1024, stdout);
        let mut parser = DiffParser::new(self.limits);
        let mut commits: Vec<GitCommitDiff> = Vec::new();
        let mut index: HashMap<String, usize> = HashMap::new();
        let mut current: Option<usize> = None;

        for line_res in reader.lines() {
            let line = match line_res {
                Ok(l) => l,
                Err(_) => continue,
            };

            if let Some(meta) = line.strip_prefix("COMMIT_META\t") {
                let mut parts = meta.splitn(4, '\t');
                let commit_id = parts.next().unwrap_or("unknown").to_string();
                let author = parts.next().unwrap_or("unknown").to_string();
                let date = parts.next().unwrap_or("unknown").to_string();
                let message = parts.next().unwrap_or("").to_string();

                current = Some(match index.get(&commit_id) {
                    Some(&existing) => existing,
                    None => {
                        let position = commits.len();
                        commits.push(GitCommitDiff {
                            commit_id: commit_id.clone(),
                            author,
                            date,
                            message,
                            added_lines: Vec::new(),
                        });
                        index.insert(commit_id, position);
                        position
                    }
                });

                parser.start_commit();
                continue;
            }

            if line.starts_with("diff --git ") {
                parser.start_file(parse_diff_header(&line));
                continue;
            }

            if let Some(position) = current {
                parser.consume(&line, &mut commits[position].added_lines);
            }
        }

        let status = child.wait();
        let stderr_output = stderr_reader
            .and_then(|handle| handle.join().ok())
            .unwrap_or_default();

        match status {
            Ok(exit) if !exit.success() => {
                let detail = stderr_output
                    .lines()
                    .rev()
                    .find(|line| !line.trim().is_empty())
                    .unwrap_or("git log failed");
                return Err(format!(
                    "git log failed in '{}': {}",
                    self.repo_path.display(),
                    detail.trim()
                ));
            }
            Err(e) => return Err(format!("Failed to wait for git log: {}", e)),
            _ => {}
        }

        let mut skipped_lines = parser.skipped_lines;
        let mut skipped_files = parser.skipped_files;

        if self.include_dangling {
            for sha in self.find_dangling_commits() {
                if index.contains_key(&sha) {
                    continue;
                }
                if let Ok(dangling) = self.collect_single_commit(&sha) {
                    skipped_lines += dangling.skipped_lines;
                    skipped_files += dangling.skipped_files;
                    if let Some(commit) = dangling.commits.into_iter().next() {
                        index.insert(sha, commits.len());
                        commits.push(commit);
                    }
                }
            }
        }

        if self.scope.include_submodules {
            for (prefix, sub_path) in self.initialized_submodules() {
                let mut sub_scope = self.scope.clone();
                sub_scope.include_submodules = false;
                sub_scope.rev_range = None;
                sub_scope.allow_empty = true;

                let sub_engine =
                    GitEngine::new(&sub_path, false, self.max_commits, self.limits)
                        .with_scope(sub_scope);

                if let Ok(sub_history) = sub_engine.collect_all_commits() {
                    skipped_lines += sub_history.skipped_lines;
                    skipped_files += sub_history.skipped_files;

                    for mut commit in sub_history.commits {
                        for line in &mut commit.added_lines {
                            line.file_path = format!("{}/{}", prefix, line.file_path);
                        }
                        commits.push(commit);
                    }
                }
            }
        }

        if self.scope.include_notes {
            commits.extend(self.collect_notes());
        }

        if self.scope.include_lfs {
            commits.extend(self.collect_lfs_objects());
        }

        if commits.is_empty() {
            if self.scope.allow_empty {
                return Ok(HistoryScan {
                    commits,
                    skipped_lines,
                    skipped_files,
                });
            }

            let reason = if self.scope.rev_range.is_some()
                || self.scope.since.is_some()
                || self.scope.until.is_some()
            {
                "no commits matched the requested range or date filter"
            } else {
                "contains no commits to scan (empty or unborn HEAD)"
            };

            return Err(format!(
                "repository '{}' {}",
                self.repo_path.display(),
                reason
            ));
        }

        Ok(HistoryScan {
            commits,
            skipped_lines,
            skipped_files,
        })
    }

    fn initialized_submodules(&self) -> Vec<(String, PathBuf)> {
        let output = match self
            .git()
            .args(["submodule", "status", "--recursive"])
            .output()
        {
            Ok(output) if output.status.success() => output,
            _ => return Vec::new(),
        };

        let mut submodules = Vec::new();

        for line in String::from_utf8_lossy(&output.stdout).lines() {
            let trimmed = line.trim_start();

            if trimmed.starts_with('-') || trimmed.starts_with('U') {
                continue;
            }

            let mut parts = trimmed.split_whitespace();
            let _sha = parts.next();
            let Some(path) = parts.next() else {
                continue;
            };

            let full_path = self.repo_path.join(path);

            if full_path.join(".git").exists() {
                submodules.push((path.to_string(), full_path));
            }
        }

        submodules
    }

    fn collect_notes(&self) -> Vec<GitCommitDiff> {
        let refs_output = match self
            .git()
            .args(["for-each-ref", "--format=%(refname)", "refs/notes"])
            .output()
        {
            Ok(output) if output.status.success() => output,
            _ => return Vec::new(),
        };

        let mut commits = Vec::new();

        for reference in String::from_utf8_lossy(&refs_output.stdout)
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
        {
            let tree_output = match self.git().args(["ls-tree", "-r", reference]).output() {
                Ok(output) if output.status.success() => output,
                _ => continue,
            };

            let mut added_lines = Vec::new();

            for entry in String::from_utf8_lossy(&tree_output.stdout).lines() {
                let Some((meta, path)) = entry.split_once('\t') else {
                    continue;
                };

                let mut parts = meta.split_whitespace();
                let (Some(_mode), Some(kind), Some(sha)) =
                    (parts.next(), parts.next(), parts.next())
                else {
                    continue;
                };

                if kind != "blob" {
                    continue;
                }

                let content = match self.git().args(["cat-file", "-p", sha]).output() {
                    Ok(output) if output.status.success() => output,
                    _ => continue,
                };

                if content.stdout.len() > self.limits.max_file_size {
                    continue;
                }

                let text = String::from_utf8_lossy(&content.stdout);

                if text.contains('\0') {
                    continue;
                }

                for (offset, line) in text.lines().enumerate() {
                    added_lines.push(DiffLine {
                        file_path: format!(
                            "{}:{}",
                            reference.trim_start_matches("refs/notes/"),
                            path
                        ),
                        line_number: offset + 1,
                        content: self.cap_line(line),
                    });
                }
            }

            if !added_lines.is_empty() {
                commits.push(GitCommitDiff {
                    commit_id: format!("notes:{}", reference),
                    author: "Git Notes".to_string(),
                    date: "Git Notes".to_string(),
                    message: String::new(),
                    added_lines,
                });
            }
        }

        commits
    }

    fn collect_lfs_objects(&self) -> Vec<GitCommitDiff> {
        let root = self.repo_path.join(".git").join("lfs").join("objects");

        if !root.is_dir() {
            return Vec::new();
        }

        let mut added_lines = Vec::new();
        let mut stack = vec![root.clone()];
        let mut files = 0;

        while let Some(directory) = stack.pop() {
            let Ok(entries) = std::fs::read_dir(&directory) else {
                continue;
            };

            for entry in entries.flatten() {
                let path = entry.path();

                if path.is_dir() {
                    stack.push(path);
                    continue;
                }

                if files >= 5000 {
                    break;
                }

                files += 1;

                let Ok(metadata) = entry.metadata() else {
                    continue;
                };

                if metadata.len() as usize > self.limits.max_file_size {
                    continue;
                }

                let Ok(bytes) = std::fs::read(&path) else {
                    continue;
                };

                let relative = path
                    .strip_prefix(&root)
                    .unwrap_or(&path)
                    .display()
                    .to_string();

                for (index, run) in printable_runs(&bytes, 16, 4000).into_iter().enumerate() {
                    added_lines.push(DiffLine {
                        file_path: format!("lfs:{}", relative),
                        line_number: index + 1,
                        content: self.cap_line(&run),
                    });
                }
            }
        }

        if added_lines.is_empty() {
            return Vec::new();
        }

        vec![GitCommitDiff {
            commit_id: "LFS_OBJECTS".to_string(),
            author: "Git LFS".to_string(),
            date: "Local LFS objects".to_string(),
            message: String::new(),
            added_lines,
        }]
    }

    fn cap_line(&self, line: &str) -> String {
        if self.limits.max_line_len > 0 && line.len() > self.limits.max_line_len {
            truncate_at_char_boundary(line, self.limits.max_line_len).to_string()
        } else {
            line.to_string()
        }
    }

    fn find_dangling_commits(&self) -> Vec<String> {
        let output = match self
            .git()
            .args(["fsck", "--unreachable", "--no-progress"])
            .output()
        {
            Ok(o) => o,
            Err(_) => return Vec::new(),
        };

        if !output.status.success() {
            return Vec::new();
        }

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

    fn collect_single_commit(&self, sha: &str) -> Result<HistoryScan, String> {
        let output = self
            .git()
            .args([
                "-c",
                "core.quotepath=false",
                "log",
                "-1",
                "--date=iso",
                "--format=COMMIT_META%x09%H%x09%an%x09%ad%x09%s",
                "-p",
                "-U0",
                sha,
            ])
            .output()
            .map_err(|e| format!("Failed to read commit {}: {}", sha, e))?;

        if !output.status.success() {
            return Err(format!("Failed to read dangling commit {}", sha));
        }

        let reader = BufReader::new(&output.stdout[..]);
        let mut parser = DiffParser::new(self.limits);
        let mut commit = GitCommitDiff {
            commit_id: sha.to_string(),
            author: "Dangling Commit".to_string(),
            date: "Unknown".to_string(),
            message: "Unreferenced / Dangling".to_string(),
            added_lines: Vec::new(),
        };

        for line_res in reader.lines() {
            let line = line_res.unwrap_or_default();

            if let Some(meta) = line.strip_prefix("COMMIT_META\t") {
                let mut parts = meta.splitn(4, '\t');
                if let (Some(id), Some(author), Some(date), Some(message)) = (
                    parts.next(),
                    parts.next(),
                    parts.next(),
                    parts.next(),
                ) {
                    commit.commit_id = id.to_string();
                    commit.author = author.to_string();
                    commit.date = date.to_string();
                    commit.message = message.to_string();
                }
                parser.start_commit();
                continue;
            }

            if line.starts_with("diff --git ") {
                parser.start_file(parse_diff_header(&line));
                continue;
            }

            parser.consume(&line, &mut commit.added_lines);
        }

        Ok(HistoryScan {
            commits: vec![commit],
            skipped_lines: parser.skipped_lines,
            skipped_files: parser.skipped_files,
        })
    }
}

struct DiffParser {
    limits: CollectLimits,
    current_file: String,
    current_line_num: usize,
    file_bytes: usize,
    file_skipped: bool,
    skipped_lines: usize,
    skipped_files: usize,
}

impl DiffParser {
    fn new(limits: CollectLimits) -> Self {
        Self {
            limits,
            current_file: String::new(),
            current_line_num: 1,
            file_bytes: 0,
            file_skipped: false,
            skipped_lines: 0,
            skipped_files: 0,
        }
    }

    fn start_commit(&mut self) {
        self.current_file.clear();
        self.current_line_num = 1;
        self.file_bytes = 0;
        self.file_skipped = false;
    }

    fn start_file(&mut self, path: Option<String>) {
        self.current_file = path.unwrap_or_default();
        self.current_line_num = 1;
        self.file_bytes = 0;
        self.file_skipped = false;
    }

    fn consume(&mut self, line: &str, out: &mut Vec<DiffLine>) {
        if let Some(start) = parse_hunk_start(line) {
            self.current_line_num = start;
            return;
        }

        if !line.starts_with('+') {
            return;
        }

        if line.starts_with("+++ ") || line == "+++" {
            return;
        }

        let content = &line[1..];

        if content.as_bytes().contains(&0) {
            self.skipped_lines += 1;
            return;
        }

        if self.limits.max_file_size > 0 && self.file_bytes >= self.limits.max_file_size {
            if !self.file_skipped {
                self.file_skipped = true;
                self.skipped_files += 1;
            }
            self.skipped_lines += 1;
            self.current_line_num += 1;
            return;
        }

        self.file_bytes = self.file_bytes.saturating_add(content.len());

        let capped = if self.limits.max_line_len > 0 && content.len() > self.limits.max_line_len {
            truncate_at_char_boundary(content, self.limits.max_line_len)
        } else {
            content
        };

        out.push(DiffLine {
            file_path: self.current_file.clone(),
            line_number: self.current_line_num,
            content: capped.to_string(),
        });

        self.current_line_num += 1;
    }
}

fn parse_hunk_start(line: &str) -> Option<usize> {
    if !line.starts_with("@@ ") {
        return None;
    }

    let plus = line.find('+')?;
    let digits: String = line[plus + 1..]
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect();

    digits.parse::<usize>().ok()
}

fn truncate_at_char_boundary(input: &str, max: usize) -> &str {
    if input.len() <= max {
        return input;
    }

    let mut end = max;
    while end > 0 && !input.is_char_boundary(end) {
        end -= 1;
    }

    &input[..end]
}

fn printable_runs(bytes: &[u8], min_len: usize, max_runs: usize) -> Vec<String> {
    let mut runs = Vec::new();
    let mut current: Vec<u8> = Vec::new();

    for &byte in bytes {
        if (0x20..=0x7e).contains(&byte) || byte == b'\t' {
            current.push(byte);
            continue;
        }

        if current.len() >= min_len {
            runs.push(String::from_utf8_lossy(&current).to_string());

            if runs.len() >= max_runs {
                return runs;
            }
        }

        current.clear();
    }

    if current.len() >= min_len && runs.len() < max_runs {
        runs.push(String::from_utf8_lossy(&current).to_string());
    }

    runs
}

fn parse_diff_header(header: &str) -> Option<String> {
    let rest = header.strip_prefix("diff --git ")?;

    if let Some(position) = rest.rfind(" \"b/") {
        let raw = &rest[position + 2..];
        let path = unquote_path(raw);
        return Some(path.strip_prefix("b/").unwrap_or(&path).to_string());
    }

    if let Some(position) = rest.rfind(" b/") {
        let raw = &rest[position + 1..];
        return Some(raw.strip_prefix("b/").unwrap_or(raw).to_string());
    }

    None
}

fn unquote_path(raw: &str) -> String {
    let inner = raw.strip_prefix('"').unwrap_or(raw);
    let inner = inner.strip_suffix('"').unwrap_or(inner);
    let bytes = inner.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;

    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 1 < bytes.len() {
            let mut octal_len = 0;
            while octal_len < 3
                && i + 1 + octal_len < bytes.len()
                && (b'0'..=b'7').contains(&bytes[i + 1 + octal_len])
            {
                octal_len += 1;
            }

            if octal_len > 0 {
                let mut value: u32 = 0;
                for k in 0..octal_len {
                    value = value * 8 + (bytes[i + 1 + k] - b'0') as u32;
                }
                out.push(value as u8);
                i += 1 + octal_len;
                continue;
            }

            let mapped = match bytes[i + 1] {
                b'n' => b'\n',
                b't' => b'\t',
                b'r' => b'\r',
                b'"' => b'"',
                b'\\' => b'\\',
                other => other,
            };
            out.push(mapped);
            i += 2;
            continue;
        }

        out.push(bytes[i]);
        i += 1;
    }

    String::from_utf8_lossy(&out).to_string()
}
