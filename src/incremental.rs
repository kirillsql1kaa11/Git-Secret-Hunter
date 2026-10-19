use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ScanMarkers {
    #[serde(skip)]
    path: Option<PathBuf>,
    entries: BTreeMap<String, String>,
}

impl ScanMarkers {
    pub fn load() -> Self {
        match Self::path() {
            Some(path) => Self::at_path(path),
            None => Self::default(),
        }
    }

    pub fn at_path(path: PathBuf) -> Self {
        let mut markers = Self {
            path: Some(path),
            entries: BTreeMap::new(),
        };

        if let Some(path) = &markers.path {
            if let Ok(contents) = fs::read_to_string(path) {
                if let Ok(entries) = serde_json::from_str::<BTreeMap<String, String>>(&contents) {
                    markers.entries = entries;
                }
            }
        }

        markers
    }

    pub fn last_commit(&self, repo: &Path) -> Option<String> {
        self.entries.get(&repo_key(repo)).cloned()
    }

    pub fn record(&mut self, repo: &Path, commit: &str) {
        self.entries.insert(repo_key(repo), commit.to_string());
    }

    pub fn save(&self) {
        let Some(path) = self.path.clone().or_else(Self::path) else {
            return;
        };

        if let Some(parent) = path.parent() {
            if fs::create_dir_all(parent).is_err() {
                return;
            }
        }

        if let Ok(json) = serde_json::to_string_pretty(&self.entries) {
            let _ = fs::write(path, json);
        }
    }

    fn path() -> Option<PathBuf> {
        if let Ok(custom) = std::env::var("GSH_SCAN_STATE") {
            if !custom.is_empty() {
                return Some(PathBuf::from(custom));
            }
        }

        if let Ok(appdata) = std::env::var("APPDATA") {
            if !appdata.is_empty() {
                return Some(
                    PathBuf::from(appdata)
                        .join("git-secret-hunter")
                        .join("last_scan.json"),
                );
            }
        }

        if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
            if !xdg.is_empty() {
                return Some(
                    PathBuf::from(xdg)
                        .join("git-secret-hunter")
                        .join("last_scan.json"),
                );
            }
        }

        if let Ok(home) = std::env::var("HOME") {
            if !home.is_empty() {
                return Some(
                    PathBuf::from(home)
                        .join(".config")
                        .join("git-secret-hunter")
                        .join("last_scan.json"),
                );
            }
        }

        None
    }
}

pub fn repo_key(repo: &Path) -> String {
    let canonical = fs::canonicalize(repo).unwrap_or_else(|_| repo.to_path_buf());
    canonical.display().to_string()
}

pub fn head_commit(repo: &Path) -> Option<String> {
    let output = Command::new("git")
        .current_dir(repo)
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let commit = String::from_utf8_lossy(&output.stdout).trim().to_string();

    if commit.is_empty() {
        None
    } else {
        Some(commit)
    }
}

fn commit_exists(repo: &Path, commit: &str) -> bool {
    Command::new("git")
        .current_dir(repo)
        .args(["cat-file", "-e", &format!("{}^{{commit}}", commit)])
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

pub fn incremental_range(repo: &Path, markers: &ScanMarkers) -> Option<String> {
    let last = markers.last_commit(repo)?;

    if !commit_exists(repo, &last) {
        return None;
    }

    Some(format!("{}..HEAD", last))
}

pub fn record_head(repo: &Path, markers: &mut ScanMarkers) {
    if let Some(commit) = head_commit(repo) {
        markers.record(repo, &commit);
        markers.save();
    }
}
