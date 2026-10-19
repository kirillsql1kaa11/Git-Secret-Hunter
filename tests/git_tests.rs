use git_secret_hunter::git::{CollectLimits, CollectScope, GitEngine};
use git_secret_hunter::incremental::{ScanMarkers, incremental_range, record_head};
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

fn scan_history(history: &git_secret_hunter::git::HistoryScan) -> Vec<git_secret_hunter::scanner::Finding> {
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

    findings
}

#[test]
fn test_commit_range_scan() {
    let Some(repo) = TempRepo::new("commit-range") else {
        return;
    };

    repo.write("one.py", "API_KEY=8fA7b9Xq2WpZ0kL9mJ1vN3cR8tY6uIo5E\n");
    repo.commit("first");
    repo.write("two.py", "API_KEY=Zq3Wp8Rt5Yb2Nm9Kv4Xc7Ld1Fs6Gh0Jm3\n");
    repo.commit("second");
    repo.write("three.py", "API_KEY=Kx7Wm2Np9Qr4Tz6Bv1Yc3Ld8Hs5Jf0Gs2\n");
    repo.commit("third");

    let scope = CollectScope {
        rev_range: Some("HEAD~1..HEAD".to_string()),
        ..CollectScope::default()
    };

    let history = GitEngine::new(repo.path(), false, None, CollectLimits::default())
        .with_scope(scope)
        .collect_all_commits()
        .expect("range collection must succeed");

    assert_eq!(history.commits.len(), 1, "only the last commit must be scanned");

    let files: Vec<String> = history
        .commits
        .iter()
        .flat_map(|commit| commit.added_lines.iter().map(|line| line.file_path.clone()))
        .collect();

    assert!(files.iter().any(|file| file.contains("three.py")));
    assert!(!files.iter().any(|file| file.contains("one.py") || file.contains("two.py")));
}

#[test]
fn test_incremental_scan_uses_recorded_marker() {
    let Some(repo) = TempRepo::new("incremental") else {
        return;
    };

    repo.write("a.py", "value = 1\n");
    repo.commit("first");

    let state_path = std::env::temp_dir().join(format!(
        "gsh-markers-{}-{}.json",
        std::process::id(),
        "incremental"
    ));

    let _ = std::fs::remove_file(&state_path);

    let mut markers = ScanMarkers::at_path(state_path.clone());
    record_head(repo.path(), &mut markers);

    assert!(
        markers.last_commit(repo.path()).is_some(),
        "marker must be recorded"
    );

    repo.write(
        "b.py",
        &format!("OPENAI_API_KEY={}\n", openai_key()),
    );
    repo.commit("second");

    let range = incremental_range(repo.path(), &markers).expect("range must be derived");
    let scope = CollectScope {
        rev_range: Some(range),
        allow_empty: true,
        ..CollectScope::default()
    };

    let history = GitEngine::new(repo.path(), false, None, CollectLimits::default())
        .with_scope(scope)
        .collect_all_commits()
        .expect("incremental collection must succeed");

    assert_eq!(history.commits.len(), 1, "only the new commit must be scanned");

    let findings = scan_history(&history);

    assert!(
        findings.iter().any(|finding| finding.rule_id == "openai-api-key"),
        "secret from the new commit must be detected"
    );

    record_head(repo.path(), &mut markers);

    let scope = CollectScope {
        rev_range: incremental_range(repo.path(), &markers),
        allow_empty: true,
        ..CollectScope::default()
    };

    let history = GitEngine::new(repo.path(), false, None, CollectLimits::default())
        .with_scope(scope)
        .collect_all_commits()
        .expect("empty incremental range must not fail");

    assert_eq!(history.commits.len(), 0, "no new commits means empty scan");

    let _ = std::fs::remove_file(&state_path);
}

#[test]
fn test_git_notes_are_scanned_when_requested() {
    let Some(repo) = TempRepo::new("notes") else {
        return;
    };

    repo.write("app.py", "value = 1\n");
    repo.commit("base");

    let note = format!("reviewer note: api_key={}", openai_key());
    repo.git(&["notes", "add", "-m", &note]);

    let scope = CollectScope {
        include_notes: true,
        ..CollectScope::default()
    };

    let history = GitEngine::new(repo.path(), false, None, CollectLimits::default())
        .with_scope(scope)
        .collect_all_commits()
        .expect("notes collection must succeed");

    assert!(
        history
            .commits
            .iter()
            .any(|commit| commit.commit_id.starts_with("notes:")),
        "notes must be attached as a synthetic commit"
    );

    let findings = scan_history(&history);

    assert!(
        findings.iter().any(|finding| finding.rule_id == "openai-api-key"),
        "secret stored in git notes must be detected"
    );
}

#[test]
fn test_lfs_objects_are_scanned_when_requested() {
    let Some(repo) = TempRepo::new("lfs") else {
        return;
    };

    repo.write("app.py", "value = 1\n");
    repo.commit("base");

    let lfs_dir = repo
        .path()
        .join(".git")
        .join("lfs")
        .join("objects")
        .join("ab")
        .join("cd");
    std::fs::create_dir_all(&lfs_dir).expect("lfs dir must be created");

    let payload = format!(
        "\u{0}\u{1}binary prefix\naws_config: api_key = \"{}\"\nbinary suffix\u{2}\u{3}",
        openai_key()
    );

    std::fs::write(
        lfs_dir.join("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"),
        payload,
    )
    .expect("lfs object must be written");

    let scope = CollectScope {
        include_lfs: true,
        ..CollectScope::default()
    };

    let history = GitEngine::new(repo.path(), false, None, CollectLimits::default())
        .with_scope(scope)
        .collect_all_commits()
        .expect("lfs collection must succeed");

    assert!(
        history
            .commits
            .iter()
            .any(|commit| commit.commit_id == "LFS_OBJECTS"),
        "lfs objects must be attached as a synthetic commit"
    );

    let findings = scan_history(&history);

    assert!(
        findings.iter().any(|finding| finding.rule_id == "openai-api-key"),
        "secret stored inside a Git LFS object must be detected"
    );
}

#[test]
fn test_stash_and_tag_commits_are_scanned() {
    let Some(repo) = TempRepo::new("stash-tag") else {
        return;
    };

    repo.write("app.py", "value = 1\n");
    repo.commit("base");

    repo.write(
        "t.py",
        &format!("TAGGED_KEY={}\n", openai_key()),
    );
    repo.commit("tagged commit");
    repo.git(&["tag", "v1.0"]);

    repo.write("t.py", "value = 1\n");
    repo.commit("remove secret");

    repo.write(
        "t.py",
        &format!("STASHED_KEY={}\n", openai_key()),
    );
    repo.git(&["stash", "push", "-q", "-m", "wip"]);

    let history = engine(repo.path(), false)
        .collect_all_commits()
        .expect("history collection must succeed");

    let commit_messages: Vec<String> = history
        .commits
        .iter()
        .map(|commit| commit.message.clone())
        .collect();

    assert!(
        commit_messages.iter().any(|message| message.contains("tagged commit")),
        "tagged commits must be included, got {:?}",
        commit_messages
    );

    let findings = scan_history(&history);

    assert!(
        findings.iter().any(|finding| finding.rule_id == "openai-api-key"),
        "secret stashed away must still be found in history"
    );
}
