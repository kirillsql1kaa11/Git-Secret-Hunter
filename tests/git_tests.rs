use git_secret_hunter::git::{CollectLimits, GitEngine};
use git_secret_hunter::scanner::{group_findings, Scanner};
use std::path::{Path, PathBuf};
use std::process::Command;

struct TempRepo {
    path: PathBuf,
}

impl TempRepo {
    fn new(name: &str) -> Option<Self> {
        if Command::new("git").arg("--version").output().is_err() {
            return None;
        }

        let path = std::env::temp_dir().join(format!(
            "gsh-test-{}-{}",
            name,
            std::process::id()
        ));

        if path.exists() {
            let _ = std::fs::remove_dir_all(&path);
        }

        std::fs::create_dir_all(&path).ok()?;

        let repo = Self { path };
        repo.git(&["init", "-q", "-b", "main"]);
        repo.git(&["config", "user.email", "test@example.com"]);
        repo.git(&["config", "user.name", "Test"]);
        Some(repo)
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn git(&self, args: &[&str]) -> String {
        let output = Command::new("git")
            .args(args)
            .current_dir(&self.path)
            .output()
            .expect("git command failed to start");

        String::from_utf8_lossy(&output.stdout).to_string()
    }

    fn write(&self, relative: &str, content: &str) {
        let full = self.path.join(relative);
        if let Some(parent) = full.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        std::fs::write(full, content).expect("failed to write test file");
    }

    fn commit(&self, message: &str) {
        self.git(&["add", "-A"]);
        self.git(&["commit", "-q", "-m", message]);
    }
}

impl Drop for TempRepo {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

fn engine(path: &Path, include_dangling: bool) -> GitEngine {
    GitEngine::new(path, include_dangling, None, CollectLimits::default())
}

fn openai_key() -> String {
    format!("{}{}", "sk-proj-", "uR8xL9pQ2mK5vN4wZ7tY1sA0bC3dE6fG8hI0jK2lM4nP6qS8")
}

#[test]
fn test_merge_resolution_secrets_are_scanned() {
    let Some(repo) = TempRepo::new("merge") else {
        return;
    };

    repo.write("app.py", "value = 1\n");
    repo.commit("base");

    repo.git(&["checkout", "-q", "-b", "feature"]);
    repo.write("app.py", "value = 2\n");
    repo.commit("feature change");

    repo.git(&["checkout", "-q", "main"]);
    repo.write("app.py", "value = 3\n");
    repo.commit("main change");

    repo.git(&["merge", "feature", "-q", "--no-edit"]);

    let leaked = format!("OPENAI_API_KEY={}\n", openai_key());
    repo.write("app.py", &leaked);
    repo.commit("merge resolution with key");

    let history = engine(repo.path(), false)
        .collect_all_commits()
        .expect("history collection must succeed");

    let scanner = Scanner::new(false, true, 4.5, 20);
    let mut findings = Vec::new();

    for commit in &history.commits {
        for line in &commit.added_lines {
            findings.extend(scanner.scan_line(
                &line.content,
                &line.file_path,
                line.line_number,
                &commit.commit_id,
                &commit.author,
                &commit.date,
            ));
        }
    }

    assert!(
        findings.iter().any(|finding| finding.rule_id == "openai-api-key"),
        "secret introduced by a merge commit must be detected, commits scanned: {}",
        history.commits.len()
    );
}

#[test]
fn test_rejects_non_repository_path() {
    let path = std::env::temp_dir().join(format!("gsh-not-a-repo-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&path);
    std::fs::write(path.join("config.py"), "API_KEY=8fA7b9Xq2WpZ0kL9mJ1vN3cR8tY6uIo5E\n").ok();

    let result = engine(&path, false).collect_all_commits();

    let _ = std::fs::remove_dir_all(&path);

    assert!(
        result.is_err(),
        "scanning a non-git folder must fail loudly instead of reporting success"
    );
}

#[test]
fn test_empty_repository_reports_error() {
    let Some(repo) = TempRepo::new("empty") else {
        return;
    };

    let result = engine(repo.path(), false).collect_all_commits();
    assert!(result.is_err(), "repository without commits must not report success");
}

#[test]
fn test_non_ascii_paths_are_preserved() {
    let Some(repo) = TempRepo::new("cyrillic") else {
        return;
    };

    let secret = "8fA7b9Xq2WpZ0kL9mJ1vN3cR8tY6uIo5E";
    repo.write("секреты.py", &format!("API_KEY={}\n", secret));
    repo.commit("cyrillic filename");

    let history = engine(repo.path(), false)
        .collect_all_commits()
        .expect("history collection must succeed");

    let paths: Vec<String> = history
        .commits
        .iter()
        .flat_map(|commit| commit.added_lines.iter().map(|line| line.file_path.clone()))
        .collect();

    assert!(
        paths.iter().any(|path| path.contains("секреты")),
        "quoted git paths must be decoded, got {:?}",
        paths
    );
}

#[test]
fn test_dangling_commits_are_scanned_when_enabled() {
    let Some(repo) = TempRepo::new("dangling") else {
        return;
    };

    repo.write("readme.txt", "clean\n");
    repo.commit("base");

    repo.write("leak.txt", &format!("OPENAI_API_KEY={}\n", openai_key()));
    repo.commit("leak commit");

    repo.git(&["reset", "-q", "--hard", "HEAD~1"]);
    repo.git(&["reflog", "expire", "--expire=now", "--expire-unreachable=now", "--all"]);

    let unreachable = repo.git(&["fsck", "--unreachable", "--no-progress"]);
    if !unreachable.contains("commit ") {
        return;
    }

    let history = engine(repo.path(), true)
        .collect_all_commits()
        .expect("history collection must succeed");

    let scanner = Scanner::new(false, true, 4.5, 20);
    let mut findings = Vec::new();

    for commit in &history.commits {
        for line in &commit.added_lines {
            findings.extend(scanner.scan_line(
                &line.content,
                &line.file_path,
                line.line_number,
                &commit.commit_id,
                &commit.author,
                &commit.date,
            ));
        }
    }

    assert!(
        findings.iter().any(|finding| finding.rule_id == "openai-api-key"),
        "dangling commit secret must be detected"
    );
}

#[test]
fn test_limits_cap_lines_and_file_budget() {
    let Some(repo) = TempRepo::new("limits") else {
        return;
    };

    let tail = "y".repeat(2048);
    let mut content = format!("API_TOKEN=8fA7b9Xq2WpZ0kL9mJ1vN3cR8tY6uIo5E;{}\n", tail);
    for index in 0..40 {
        content.push_str(&format!("line {:03} of the oversized file payload\n", index));
    }
    repo.write("huge.py", &content);

    repo.commit("limits");

    let limits = CollectLimits {
        max_line_len: 128,
        max_file_size: 256,
    };

    let history = GitEngine::new(repo.path(), false, None, limits)
        .collect_all_commits()
        .expect("history collection must succeed");

    assert!(
        history
            .commits
            .iter()
            .flat_map(|commit| commit.added_lines.iter())
            .all(|line| line.content.len() <= 128),
        "lines longer than max_line_len must be capped"
    );

    assert!(
        history.skipped_files >= 1,
        "files exceeding max_file_size must be skipped and counted"
    );

    assert!(
        history.skipped_lines >= 1,
        "lines beyond the file budget must be skipped and counted"
    );

    let scanner = Scanner::new(false, true, 4.5, 20);
    let mut findings = Vec::new();

    for commit in &history.commits {
        for line in &commit.added_lines {
            findings.extend(scanner.scan_line(
                &line.content,
                &line.file_path,
                line.line_number,
                &commit.commit_id,
                &commit.author,
                &commit.date,
            ));
        }
    }

    assert!(
        findings
            .iter()
            .any(|finding| finding.rule_id == "high-entropy-token"),
        "secret at the start of a capped line must still be detected"
    );

    assert!(group_findings(&findings).len() >= 1);
}
