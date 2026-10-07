#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContextScore {
    HighConfidence,
    Normal,
    LowConfidence,
    FalsePositive,
}

pub fn is_ignored_path(path: &str) -> bool {
    let normalized = path.replace('\\', "/").to_lowercase();

    let ignored_dir_segments = [
        "/venv/",
        "venv/",
        "/.venv/",
        ".venv/",
        "/env/",
        "env/",
        "/site-packages/",
        "site-packages/",
        "/node_modules/",
        "node_modules/",
        "/vendor/",
        "vendor/",
        ".dist-info/",
        ".egg-info/",
        "/__pycache__/",
        "__pycache__/",
        "/.git/",
        ".git/",
    ];

    for segment in ignored_dir_segments {
        if normalized.contains(segment) {
            return true;
        }
    }

    let ignored_extensions = [
        ".lock",
        ".min.js",
        ".min.css",
        ".map",
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".svg",
        ".ico",
        ".webp",
        ".woff",
        ".woff2",
        ".ttf",
        ".eot",
        ".mp4",
        ".mp3",
        ".pdf",
        ".zip",
        ".tar",
        ".gz",
        ".bin",
        ".exe",
        ".dll",
        ".so",
        ".dylib",
        ".pem",
        ".crt",
        ".cer",
        ".der",
    ];

    for ext in ignored_extensions {
        if normalized.ends_with(ext) {
            return true;
        }
    }

    let ignored_files = [
        "package-lock.json",
        "cargo.lock",
        "yarn.lock",
        "pnpm-lock.yaml",
        "composer.lock",
        "gemfile.lock",
        "poetry.lock",
        "go.sum",
        "record",
        "installer",
        "wheel",
        "metadata",
    ];

    for file in ignored_files {
        if normalized.ends_with(file) {
            return true;
        }
    }

    false
}

pub fn evaluate_context(line: &str, file_path: &str, token: &str) -> ContextScore {
    let lower_line = line.to_lowercase();
    let lower_path = file_path.to_lowercase();
    let lower_token = token.to_lowercase();

    if is_false_positive_token(&lower_token) {
        return ContextScore::FalsePositive;
    }

    let is_test_environment = lower_path.contains("test")
        || lower_path.contains("fixture")
        || lower_path.contains("mock")
        || lower_path.contains("spec");

    let mock_indicators = [
        "mock",
        "fake",
        "dummy",
        "sample",
        "example",
        "placeholder",
        "stub",
        "insert_here",
    ];

    for indicator in mock_indicators {
        if lower_line.contains(indicator) {
            return if is_test_environment {
                ContextScore::FalsePositive
            } else {
                ContextScore::LowConfidence
            };
        }
    }

    let secret_keywords = [
        "api_key",
        "apikey",
        "secret",
        "token",
        "bearer",
        "auth",
        "credentials",
        "password",
        "private_key",
    ];

    for kw in secret_keywords {
        if lower_line.contains(kw) {
            return ContextScore::HighConfidence;
        }
    }

    if lower_path.ends_with(".env")
        || lower_path.contains(".env.")
        || lower_path.ends_with("credentials.json")
    {
        return ContextScore::HighConfidence;
    }

    if is_test_environment {
        ContextScore::LowConfidence
    } else {
        ContextScore::Normal
    }
}

pub fn is_false_positive_token(token: &str) -> bool {
    let lower = token.to_lowercase();

    let dummy_words = [
        "example",
        "dummy",
        "sample",
        "placeholder",
        "test_key",
        "fake",
        "abcdef",
        "123456",
        "xxxxxxxx",
        "your_api_key",
        "insert_here",
        "secret_here",
    ];

    for dummy in dummy_words {
        if lower.contains(dummy) {
            return true;
        }
    }

    if is_uuid(&lower) {
        return true;
    }

    if is_pure_hex_hash(&lower) {
        return true;
    }

    false
}

fn is_uuid(s: &str) -> bool {
    let parts: Vec<&str> = s.split('-').collect();
    if parts.len() != 5 {
        return false;
    }

    parts[0].len() == 8
        && parts[1].len() == 4
        && parts[2].len() == 4
        && parts[3].len() == 4
        && parts[4].len() == 12
        && parts.iter().all(|p| p.chars().all(|c| c.is_ascii_hexdigit()))
}

fn is_pure_hex_hash(s: &str) -> bool {
    (s.len() == 32 || s.len() == 40 || s.len() == 64)
        && s.chars().all(|c| c.is_ascii_hexdigit())
}
