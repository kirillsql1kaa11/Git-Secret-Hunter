use rand::Rng;
use reqwest::blocking::Client;
use reqwest::header::{HeaderMap, HeaderValue, ACCEPT, AUTHORIZATION, USER_AGENT};
use serde::Deserialize;
use std::thread::sleep;
use std::time::Duration;

#[derive(Debug, Clone, Deserialize)]
pub struct GitHubRepo {
    pub id: u64,
    pub name: String,
    pub full_name: String,
    pub html_url: String,
    #[serde(default)]
    pub description: Option<String>,
}

impl GitHubRepo {
    pub fn clone_url(&self) -> String {
        format!("{}.git", self.html_url)
    }
}

#[derive(Debug, Deserialize)]
struct SearchResponse {
    items: Vec<GitHubRepo>,
}

pub struct GitHubClient {
    client: Client,
}

impl GitHubClient {
    pub fn new(token: Option<&str>) -> Result<Self, String> {
        let mut headers = HeaderMap::new();
        headers.insert(
            USER_AGENT,
            HeaderValue::from_static("GitSecretHunter-SecurityAuditor/0.1.0"),
        );
        headers.insert(
            ACCEPT,
            HeaderValue::from_static("application/vnd.github+json"),
        );

        if let Some(tok) = token {
            let auth_value = format!("Bearer {}", tok);
            if let Ok(val) = HeaderValue::from_str(&auth_value) {
                headers.insert(AUTHORIZATION, val);
            }
        }

        let client = Client::builder()
            .default_headers(headers)
            .timeout(Duration::from_secs(20))
            .build()
            .map_err(|e| format!("Failed to build HTTP client: {}", e))?;

        Ok(Self { client })
    }

    pub fn fetch_random_repos(&self, limit: usize) -> Result<Vec<GitHubRepo>, String> {
        let mut collected = Vec::new();
        let mut attempts = 0;
        let max_attempts = (limit / 20).max(10);

        while collected.len() < limit && attempts < max_attempts {
            attempts += 1;
            let random_since: u64 = rand::thread_rng().gen_range(50_000_000..950_000_000);
            let url = format!("https://api.github.com/repositories?since={}", random_since);

            let resp = match self.client.get(&url).send() {
                Ok(r) => r,
                Err(_) => {
                    sleep(Duration::from_millis(500));
                    continue;
                }
            };

            if resp.status().as_u16() == 403 {
                return Err("GitHub API Rate Limit exceeded. Provide a personal access token via --github-token.".to_string());
            }

            if !resp.status().is_success() {
                sleep(Duration::from_millis(500));
                continue;
            }

            let batch: Vec<GitHubRepo> = match resp.json() {
                Ok(b) => b,
                Err(_) => {
                    sleep(Duration::from_millis(300));
                    continue;
                }
            };

            for repo in batch {
                collected.push(repo);
                if collected.len() >= limit {
                    break;
                }
            }
        }

        if collected.is_empty() {
            return Err("Unable to reach GitHub API after multiple attempts. Check your internet connection.".to_string());
        }

        Ok(collected)
    }

    pub fn search_repos(&self, query: &str, limit: usize) -> Result<Vec<GitHubRepo>, String> {
        let mut collected = Vec::new();
        let mut page = 1;
        let mut retries = 0;

        while collected.len() < limit && retries < 5 {
            let per_page = (limit - collected.len()).min(100);
            let url = format!(
                "https://api.github.com/search/repositories?q={}&sort=updated&order=desc&per_page={}&page={}",
                urlencoding(query),
                per_page,
                page
            );

            let resp = match self.client.get(&url).send() {
                Ok(r) => r,
                Err(_) => {
                    retries += 1;
                    sleep(Duration::from_secs(1));
                    continue;
                }
            };

            if resp.status().as_u16() == 403 {
                return Err("GitHub API Rate Limit exceeded. Provide a personal access token via --github-token.".to_string());
            }

            if !resp.status().is_success() {
                retries += 1;
                sleep(Duration::from_secs(1));
                continue;
            }

            let search_resp: SearchResponse = match resp.json() {
                Ok(sr) => sr,
                Err(_) => {
                    retries += 1;
                    sleep(Duration::from_millis(500));
                    continue;
                }
            };

            if search_resp.items.is_empty() {
                break;
            }

            for repo in search_resp.items {
                collected.push(repo);
                if collected.len() >= limit {
                    break;
                }
            }

            page += 1;
        }

        if collected.is_empty() {
            return Err("Search yielded no results or network connection failed.".to_string());
        }

        Ok(collected)
    }
}

fn urlencoding(input: &str) -> String {
    let mut encoded = String::new();
    for byte in input.bytes() {
        match byte {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                encoded.push(byte as char);
            }
            _ => {
                encoded.push_str(&format!("%{:02X}", byte));
            }
        }
    }
    encoded
}
