use regex::Regex;
use std::sync::OnceLock;

fn candidate_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"[A-Za-z0-9+/=_\-.]{4,256}").expect("valid candidate pattern"))
}

fn identifier_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"^[A-Za-z_][A-Za-z0-9_.\-]{0,40}$").expect("valid identifier pattern")
    })
}

pub fn extract_candidates(line: &str, min_len: usize) -> Vec<String> {
    let mut candidates = Vec::new();

    for matched in candidate_regex().find_iter(line) {
        let raw = matched.as_str();
        let value = trim_edges(strip_assignment(raw));

        if value.len() < min_len || value.len() > 256 {
            continue;
        }

        if candidates.iter().any(|existing| existing == value) {
            continue;
        }

        candidates.push(value.to_string());
    }

    candidates
}

fn strip_assignment(raw: &str) -> &str {
    if let Some(position) = raw.find('=') {
        let (left, right) = raw.split_at(position);
        let right = right.trim_start_matches('=');

        if !right.is_empty() && identifier_regex().is_match(left) {
            return right;
        }
    }

    raw
}

fn trim_edges(value: &str) -> &str {
    value.trim_matches(|c: char| c == '.' || c == '-')
}
