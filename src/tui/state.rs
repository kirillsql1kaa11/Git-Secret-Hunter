use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ResolvedState {
    #[serde(skip)]
    path: Option<std::path::PathBuf>,
    entries: HashMap<String, bool>,
}

impl ResolvedState {
    pub fn load() -> Self {
        match Self::path() {
            Some(path) => Self::at_path(path),
            None => Self::default(),
        }
    }

    pub fn at_path(path: std::path::PathBuf) -> Self {
        let mut state = Self {
            path: Some(path),
            entries: HashMap::new(),
        };

        if let Some(path) = &state.path {
            if let Ok(contents) = fs::read_to_string(path) {
                if let Ok(entries) = serde_json::from_str::<HashMap<String, bool>>(&contents) {
                    state.entries = entries;
                }
            }
        }

        state
    }

    pub fn is_resolved(&self, fingerprint: &str) -> bool {
        self.entries.get(fingerprint).copied().unwrap_or(false)
    }

    pub fn toggle(&mut self, fingerprint: &str) -> bool {
        let next = !self.is_resolved(fingerprint);
        self.entries.insert(fingerprint.to_string(), next);
        self.save();
        next
    }

    pub fn resolved_count(&self) -> usize {
        self.entries.values().filter(|resolved| **resolved).count()
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
        if let Ok(custom) = std::env::var("GSH_STATE_FILE") {
            if !custom.is_empty() {
                return Some(PathBuf::from(custom));
            }
        }

        if let Ok(appdata) = std::env::var("APPDATA") {
            if !appdata.is_empty() {
                return Some(
                    PathBuf::from(appdata)
                        .join("git-secret-hunter")
                        .join("state.json"),
                );
            }
        }

        if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
            if !xdg.is_empty() {
                return Some(
                    PathBuf::from(xdg)
                        .join("git-secret-hunter")
                        .join("state.json"),
                );
            }
        }

        if let Ok(home) = std::env::var("HOME") {
            if !home.is_empty() {
                return Some(
                    PathBuf::from(home)
                        .join(".config")
                        .join("git-secret-hunter")
                        .join("state.json"),
                );
            }
        }

        None
    }
}
