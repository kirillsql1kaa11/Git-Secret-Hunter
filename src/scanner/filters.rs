#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContextScore {
    HighConfidence,
    Normal,
    LowConfidence,
    FalsePositive,
}

const HASH_CONTEXT_MARKERS: [&str; 24] = [
    "sha1",
    "sha224",
    "sha256",
    "sha384",
    "sha512",
    "sha-1",
    "sha-256",
    "md5",
    "checksum",
    "check_sum",
    "integrity",
    "etag",
    "digest",
    "objectid",
    "object_id",
    "uuid",
    "guid",
    "correlation",
    "trace_id",
    "traceid",
    "request_id",
    "requestid",
    "span_id",
    "commit",
];

const SECRET_KEYWORDS: [&str; 28] = [
    "api_key",
    "apikey",
    "api-key",
    "secret",
    "token",
    "bearer",
    "auth",
    "credentials",
    "credential",
    "password",
    "passwd",
    "private_key",
    "private key",
    "access_key",
    "secret_key",
    "ssh",
    "hash",
    "sig",
    "signature",
    "dsn",
    "connection_string",
    "connectionstring",
    "database_url",
    "webhook",
    "smtp",
    "client_secret",
    "encryption_key",
    "salt",
];

pub fn looks_like_artifact_name(token_lower: &str) -> bool {
    const EXTENSIONS: [&str; 40] = [
        "zip", "tar", "gz", "tgz", "bz2", "xz", "7z", "rar", "whl", "jar", "exe", "msi", "dll",
        "so", "dylib", "js", "mjs", "cjs", "css", "map", "json", "yml", "yaml", "toml", "lock",
        "md", "txt", "log", "csv", "xml", "ico", "png", "jpg", "jpeg", "gif", "svg", "html", "htm",
        "sql", "pem",
    ];

    let Some((name, extension)) = token_lower.rsplit_once('.') else {
        return false;
    };

    if name.is_empty() || extension.is_empty() {
        return false;
    }

    if extension
        .chars()
        .all(|character| character.is_ascii_digit())
    {
        return true;
    }

    EXTENSIONS.contains(&extension)
}

pub fn looks_like_checksum_line(line: &str) -> bool {
    let trimmed = line.trim();

    if trimmed.len() < 42 || trimmed.contains('=') {
        return false;
    }

    if trimmed.contains("-----BEGIN") {
        return false;
    }

    let mut parts = trimmed.split_whitespace();
    let Some(first) = parts.next() else {
        return false;
    };

    let digest = first.trim_end_matches(':');
    let is_digest = (32..=128).contains(&digest.len())
        && digest.chars().all(|character| character.is_ascii_hexdigit());

    if !is_digest {
        return false;
    }

    let Some(file_name) = parts.next() else {
        return false;
    };

    let file_name = file_name.trim_start_matches('*');

    !file_name.is_empty() && file_name.chars().any(|character| character.is_ascii_alphanumeric())
}

pub fn looks_like_minified_line(line: &str) -> bool {
    if line.len() < 1200 {
        return false;
    }

    let spaces = line.bytes().filter(|byte| *byte == b' ').count();
    spaces * 80 < line.len()
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
        "bun.lockb",
        "composer.lock",
        "gemfile.lock",
        "poetry.lock",
        "uv.lock",
        "pipfile.lock",
        "packages.lock.json",
        "flake.lock",
        "mix.lock",
        "pubspec.lock",
        "podfile.lock",
        "gradle.lockfile",
        ".terraform.lock.hcl",
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

pub fn has_hash_context(line_lower: &str) -> bool {
    HASH_CONTEXT_MARKERS
        .iter()
        .any(|marker| line_lower.contains(marker))
}

pub fn has_secret_keyword(line_lower: &str) -> bool {
    SECRET_KEYWORDS
        .iter()
        .any(|keyword| line_lower.contains(keyword))
}

pub fn evaluate_context(line: &str, file_path: &str, token: &str) -> ContextScore {
    let line_lower = line.to_lowercase();
    let path_lower = file_path.to_lowercase();
    let token_lower = token.to_lowercase();

    evaluate_context_lower(&line_lower, &path_lower, &token_lower)
}

pub fn evaluate_context_lower(line_lower: &str, path_lower: &str, token_lower: &str) -> ContextScore {
    if is_false_positive_token(token_lower, has_hash_context(line_lower)) {
        return ContextScore::FalsePositive;
    }

    let is_test_environment = is_test_path(path_lower);

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
        if line_lower.contains(indicator) {
            return if is_test_environment {
                ContextScore::FalsePositive
            } else {
                ContextScore::LowConfidence
            };
        }
    }

    if has_secret_keyword(line_lower) {
        return ContextScore::HighConfidence;
    }

    if path_lower.ends_with(".env")
        || path_lower.contains(".env.")
        || path_lower.ends_with("credentials.json")
    {
        return ContextScore::HighConfidence;
    }

    if is_test_environment {
        ContextScore::LowConfidence
    } else {
        ContextScore::Normal
    }
}

pub fn is_test_path(path_lower: &str) -> bool {
    path_lower.contains("test")
        || path_lower.contains("fixture")
        || path_lower.contains("mock")
        || path_lower.contains("spec")
}

pub fn is_false_positive_token(token_lower: &str, hash_context: bool) -> bool {
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
        if token_lower.contains(dummy) {
            return true;
        }
    }

    let subresource_integrity_prefixes = ["sha1-", "sha256-", "sha384-", "sha512-", "md5-", "sha3-"];
    for prefix in subresource_integrity_prefixes {
        if token_lower.starts_with(prefix) {
            return true;
        }
    }

    if is_uuid(token_lower) {
        return true;
    }

    if is_single_char_run(token_lower) {
        return true;
    }

    if hash_context && is_hex_token(token_lower) {
        return true;
    }

    false
}

pub fn is_hex_token(token_lower: &str) -> bool {
    (32..=128).contains(&token_lower.len()) && token_lower.chars().all(|c| c.is_ascii_hexdigit())
}

fn is_single_char_run(token_lower: &str) -> bool {
    let mut chars = token_lower.chars();
    match chars.next() {
        Some(first) => chars.all(|c| c == first),
        None => false,
    }
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
