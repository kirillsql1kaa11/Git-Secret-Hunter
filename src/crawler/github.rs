use rand::Rng;
use reqwest::blocking::Client;
use reqwest::header::{HeaderMap, HeaderValue, ACCEPT, AUTHORIZATION, USER_AGENT};
use serde::Deserialize;
use std::collections::HashSet;
use std::thread::sleep;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Deserialize)]
pub struct GitHubRepo {
    pub id: u64,
    pub name: String,
    pub full_name: String,
    pub html_url: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub fork: bool,
    #[serde(default)]
    pub archived: bool,
    #[serde(default)]
    pub stargazers_count: u32,
    #[serde(default)]
    pub size: u64,
    #[serde(default)]
    pub language: Option<String>,
    #[serde(default)]
    pub pushed_at: Option<String>,
}

impl GitHubRepo {
    pub fn clone_url(&self) -> String {
        format!("{}.git", self.html_url)
    }
}

#[derive(Debug, Clone)]
pub struct CrawlFilters {
    pub min_stars: u32,
    pub max_size_kb: Option<u64>,
    pub language: Option<String>,
    pub include_forks: bool,
    pub include_archived: bool,
    pub pushed_days: Option<u32>,
}

impl Default for CrawlFilters {
    fn default() -> Self {
        Self {
            min_stars: 0,
            max_size_kb: Some(500 * 1024),
            language: None,
            include_forks: false,
            include_archived: false,
            pushed_days: None,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct Discovery {
    pub repos: Vec<GitHubRepo>,
    pub skipped: usize,
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
        let user_agent = format!(
            "GitSecretHunter-SecurityAuditor/{}",
            env!("CARGO_PKG_VERSION")
        );
        headers.insert(
            USER_AGENT,
            HeaderValue::from_str(&user_agent)
                .unwrap_or_else(|_| HeaderValue::from_static("GitSecretHunter-SecurityAuditor")),
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

    pub fn discover(
        &self,
        query: Option<&str>,
        limit: usize,
        filters: &CrawlFilters,
        exclude: &HashSet<String>,
    ) -> Result<Discovery, String> {
        match query.map(str::trim).filter(|query| !query.is_empty()) {
            Some(query) => self.search_repos(query, limit, filters, exclude),
            None => self.fetch_random_repos(limit, filters, exclude),
        }
    }

    pub fn fetch_random_repos(
        &self,
        limit: usize,
        filters: &CrawlFilters,
        exclude: &HashSet<String>,
    ) -> Result<Discovery, String> {
        let mut collected = Vec::new();
        let mut skipped = 0usize;
        let mut attempts = 0;
        let max_attempts = (limit / 10).clamp(6, 30);

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
                if !matches_filters(&repo, filters) {
                    skipped += 1;
                    continue;
                }

                if exclude.contains(&repo.full_name) {
                    skipped += 1;
                    continue;
                }

                collected.push(repo);

                if collected.len() >= limit {
                    break;
                }
            }
        }

        if collected.is_empty() {
            if skipped > 0 {
                return Ok(Discovery { repos: collected, skipped });
            }

            return Err("Unable to reach GitHub API after multiple attempts. Check your internet connection.".to_string());
        }

        Ok(Discovery { repos: collected, skipped })
    }

    pub fn search_repos(
        &self,
        query: &str,
        limit: usize,
        filters: &CrawlFilters,
        exclude: &HashSet<String>,
    ) -> Result<Discovery, String> {
        let full_query = build_search_query(Some(query), filters);
        let mut collected = Vec::new();
        let mut skipped = 0usize;
        let mut pages_tried: Vec<u64> = Vec::new();
        let mut empty_pages = 0usize;
        let mut next_page: Option<u64> = Some(1);

        while collected.len() < limit {
            let page = match next_page.take() {
                Some(page) => page,
                None => {
                    let mut candidate = rand::thread_rng().gen_range(1..=10u64);
                    let mut guard = 0;

                    while pages_tried.contains(&candidate) && guard < 20 {
                        candidate = rand::thread_rng().gen_range(1..=10u64);
                        guard += 1;
                    }

                    if pages_tried.contains(&candidate) {
                        break;
                    }

                    candidate
                }
            };

            if pages_tried.contains(&page) {
                break;
            }

            pages_tried.push(page);

            let url = format!(
                "https://api.github.com/search/repositories?q={}&sort=updated&order=desc&per_page=100&page={}",
                urlencoding(&full_query),
                page
            );

            let resp = match self.client.get(&url).send() {
                Ok(r) => r,
                Err(_) => {
                    sleep(Duration::from_secs(1));
                    continue;
                }
            };

            if resp.status().as_u16() == 403 {
                return Err("GitHub API Rate Limit exceeded. Provide a personal access token via --github-token.".to_string());
            }

            if !resp.status().is_success() {
                sleep(Duration::from_secs(1));
                continue;
            }

            let search_resp: SearchResponse = match resp.json() {
                Ok(sr) => sr,
                Err(_) => {
                    sleep(Duration::from_millis(500));
                    continue;
                }
            };

            if search_resp.items.is_empty() {
                empty_pages += 1;

                if empty_pages >= 2 || pages_tried.len() >= 10 {
                    break;
                }

                continue;
            }

            empty_pages = 0;

            for repo in search_resp.items {
                if !matches_filters(&repo, filters) {
                    skipped += 1;
                    continue;
                }

                if exclude.contains(&repo.full_name) {
                    skipped += 1;
                    continue;
                }

                if collected
                    .iter()
                    .any(|existing: &GitHubRepo| existing.full_name == repo.full_name)
                {
                    continue;
                }

                collected.push(repo);

                if collected.len() >= limit {
                    break;
                }
            }

            if pages_tried.len() >= 10 {
                break;
            }
        }

        if collected.is_empty() && skipped == 0 {
            return Err("Search yielded no results or network connection failed.".to_string());
        }

        Ok(Discovery { repos: collected, skipped })
    }
}

pub fn build_search_query(base: Option<&str>, filters: &CrawlFilters) -> String {
    let mut parts: Vec<String> = Vec::new();

    if let Some(base) = base {
        let base = base.trim();

        if !base.is_empty() {
            parts.push(base.to_string());
        }
    }

    if !filters.include_forks {
        parts.push("fork:false".to_string());
    }

    if !filters.include_archived {
        parts.push("archived:false".to_string());
    }

    if filters.min_stars > 0 {
        parts.push(format!("stars:>={}", filters.min_stars));
    }

    if let Some(max_size) = filters.max_size_kb {
        if max_size > 0 {
            parts.push(format!("size:<={}", max_size));
        }
    }

    if let Some(language) = &filters.language {
        let language = language.trim();

        if !language.is_empty() {
            parts.push(format!("language:{}", language));
        }
    }

    if let Some(days) = filters.pushed_days {
        if days > 0 {
            parts.push(format!("pushed:>={}", date_days_ago(days as i64)));
        }
    }

    parts.join(" ")
}

pub fn matches_filters(repo: &GitHubRepo, filters: &CrawlFilters) -> bool {
    if !filters.include_forks && repo.fork {
        return false;
    }

    if !filters.include_archived && repo.archived {
        return false;
    }

    if repo.stargazers_count < filters.min_stars {
        return false;
    }

    if let Some(max_size) = filters.max_size_kb {
        if max_size > 0 && repo.size > max_size {
            return false;
        }
    }

    if let Some(language) = &filters.language {
        let language = language.trim();

        if !language.is_empty() {
            let matches = repo
                .language
                .as_ref()
                .map(|repo_language| repo_language.eq_ignore_ascii_case(language))
                .unwrap_or(false);

            if !matches {
                return false;
            }
        }
    }

    if let Some(days) = filters.pushed_days {
        if days > 0 {
            let Some(pushed_at) = repo.pushed_at.as_deref() else {
                return false;
            };

            let Some(pushed_days) = parse_days(pushed_at) else {
                return false;
            };

            if today_days() - pushed_days > days as i64 {
                return false;
            }
        }
    }

    true
}

pub fn today_days() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| (duration.as_secs() / 86400) as i64)
        .unwrap_or(0)
}

fn parse_days(value: &str) -> Option<i64> {
    let date = value.get(..10)?;
    let mut parts = date.split('-');
    let year: i64 = parts.next()?.parse().ok()?;
    let month: i64 = parts.next()?.parse().ok()?;
    let day: i64 = parts.next()?.parse().ok()?;

    Some(days_from_civil(year, month, day))
}

pub fn date_days_ago(days: i64) -> String {
    let (year, month, day) = civil_from_days(today_days() - days);

    format!("{:04}-{:02}-{:02}", year, month, day)
}

fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let yoe = year - era * 400;
    let month = if month > 2 { month - 3 } else { month + 9 };
    let doy = (153 * month + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;

    era * 146097 + doe - 719468
}

fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let days = days + 719468;
    let era = if days >= 0 { days } else { days - 146096 } / 146097;
    let doe = days - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { year + 1 } else { year };

    (year, month, day)
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
