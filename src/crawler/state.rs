use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_ENTRIES: usize = 50_000;

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct CrawlSeen {
    #[serde(skip)]
    path: Option<PathBuf>,
    entries: HashMap<String, u64>,
}

impl CrawlSeen {
    pub fn load() -> Self {
        match Self::path() {
            Some(path) => Self::at_path(path),
            None => Self::default(),
        }
    }

    pub fn at_path(path: PathBuf) -> Self {
        let mut seen = Self {
            path: Some(path),
            entries: HashMap::new(),
        };

        if let Some(path) = &seen.path {
            if let Ok(contents) = fs::read_to_string(path) {
                if let Ok(entries) = serde_json::from_str::<HashMap<String, u64>>(&contents) {
                    seen.entries = entries;
                }
            }
        }

        seen
    }

    pub fn as_set(&self) -> HashSet<String> {
        self.entries.keys().cloned().collect()
    }

    pub fn contains(&self, repo_name: &str) -> bool {
        self.entries.contains_key(repo_name)
    }

    pub fn record(&mut self, repo_name: &str) {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .unwrap_or(0);

        self.entries.insert(repo_name.to_string(), timestamp);
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
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

        let mut entries = self.entries.clone();

        if entries.len() > MAX_ENTRIES {
            let mut sorted: Vec<(String, u64)> = entries.into_iter().collect();
            sorted.sort_by(|left, right| right.1.cmp(&left.1));
            sorted.truncate(MAX_ENTRIES);
            entries = sorted.into_iter().collect();
        }

        if let Ok(json) = serde_json::to_string(&entries) {
            let _ = fs::write(path, json);
        }
    }

    fn path() -> Option<PathBuf> {
        if let Ok(custom) = std::env::var("GSH_CRAWL_STATE") {
            if !custom.is_empty() {
                return Some(PathBuf::from(custom));
            }
        }

        if let Ok(appdata) = std::env::var("APPDATA") {
            if !appdata.is_empty() {
                return Some(
                    PathBuf::from(appdata)
                        .join("git-secret-hunter")
                        .join("crawl_seen.json"),
                );
            }
        }

        if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
            if !xdg.is_empty() {
                return Some(
                    PathBuf::from(xdg)
                        .join("git-secret-hunter")
                        .join("crawl_seen.json"),
                );
            }
        }

        if let Ok(home) = std::env::var("HOME") {
            if !home.is_empty() {
                return Some(
                    PathBuf::from(home)
                        .join(".config")
                        .join("git-secret-hunter")
                        .join("crawl_seen.json"),
                );
            }
        }

        None
    }
}
