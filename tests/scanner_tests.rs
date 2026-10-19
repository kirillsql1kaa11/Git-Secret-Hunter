use git_secret_hunter::scanner::entropy::{analyze_candidate, calculate_shannon_entropy, CandidateFamily};
use git_secret_hunter::scanner::filters::{
    evaluate_context, has_hash_context, is_false_positive_token, ContextScore,
};
use git_secret_hunter::scanner::{group_findings, Scanner, Severity};

fn scanner() -> Scanner {
    Scanner::new(false, true, 4.5, 20)
}

fn scan_line(scanner: &Scanner, line: &str, path: &str) -> Vec<git_secret_hunter::scanner::Finding> {
    scanner.scan_line(line, path, 1, "a1b2c3d4e5", "Developer", "2026-01-01 10:00:00 +0000")
}

#[test]
fn test_detect_openai_key() {
    let prefix = String::from("s") + "k-proj-";
    let body = "uR8xL9pQ2mK5vN4wZ7tY1sA0bC3dE6fG8hI0jK2lM4nP6qS8";
    let sample_line = format!("const client = new OpenAI({{ apiKey: '{}{}' }});", prefix, body);
    let findings = scan_line(&scanner(), &sample_line, "src/ai.ts");

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_id, "openai-api-key");
}

#[test]
fn test_detect_anthropic_key() {
    let prefix = String::from("s") + "k-ant-api03-";
    let body = "xK9pL2mQ5vR8wZ1tY4sA7bC0dE3fG6hI9jK2lM5nP8qS1tU4vW7xY0zA3bC6dE9fG2hI5jK8lM1nP4qS7tU0vW3xY6zA9bC2dE5";
    let sample_line = format!("ANTHROPIC_API_KEY={}{}", prefix, body);
    let findings = scan_line(&scanner(), &sample_line, ".env");

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_id, "anthropic-api-key");
}

#[test]
fn test_detect_gemini_key() {
    let prefix = String::from("AI") + "zaSy";
    let body = "D9xK2pL5mQ8vR1wZ4tY7sA0bC3dE6fG8h";
    let sample_line = format!("export GEMINI_API_KEY=\"{}{}\"", prefix, body);
    let findings = scan_line(&scanner(), &sample_line, "deploy.sh");

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_id, "gemini-api-key");
}

#[test]
fn test_detect_deepseek_key() {
    let prefix = String::from("s") + "k-";
    let sample_line = format!("DEEPSEEK_API_KEY={}{}{}", prefix, "7b8f9e0a1c2d3e4f", "5a6b7c8d9e0f1a2b");
    let findings = scan_line(&scanner(), &sample_line, "config.env");

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_id, "deepseek-api-key");
}

#[test]
fn test_detect_huggingface_key() {
    let prefix = String::from("h") + "f_";
    let body = "uR8xL9pQ2mK5vN4wZ7tY1sA0bC3dE6fG8h";
    let sample_line = format!("token = \"{}{}\"", prefix, body);
    let findings = scan_line(&scanner(), &sample_line, "model.py");

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_id, "huggingface-token");
}

#[test]
fn test_detect_aws_key() {
    let prefix = String::from("AK") + "IA";
    let sample_line = format!("aws_access_key_id = {}{}", prefix, "IOSFODNN7QAZWSX9");
    let findings = scan_line(&scanner(), &sample_line, "credentials");

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_id, "aws-access-key-id");
}

#[test]
fn test_detect_github_pat() {
    let prefix = String::from("gh") + "p_";
    let body = "9u8v7w6x5y4z3a2b1c0d9e8f7g6h5i4j3k2l";
    let sample_line = format!("GH_TOKEN={}{}", prefix, body);
    let findings = scan_line(&scanner(), &sample_line, ".github/workflows/ci.yml");

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_id, "github-pat");
}

#[test]
fn test_detect_private_key() {
    let sample_line = String::from("-----BEGIN ") + "RSA PRIVATE KEY-----";
    let findings = scan_line(&scanner(), &sample_line, "certs/server.key");

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_id, "private-key");
}

#[test]
fn test_detect_hex_secrets() {
    let scanner = scanner();
    let hex32 = "7b8f9e0a1c2d3e4f5a6b7c8d9e0f1a2b";
    let hex40 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4";
    let hex64 = "4f7a9c2e8b1d6053ae7f2c9b4d8e1a6f3c0b7d2e5a8f1c4b9d6e3a0f7c2b5d8e";

    for (line, expected) in [
        (format!("X={}", hex32), "hex-secret-32"),
        (format!("api_key={}", hex32), "hex-secret-32"),
        (format!("SECRET_TOKEN={}", hex40), "hex-secret-40"),
        (format!("access_key={}", hex64), "hex-secret-64"),
    ] {
        let findings = scan_line(&scanner, &line, "app/config.py");
        assert!(
            findings.iter().any(|finding| finding.rule_id == expected),
            "expected {} in findings for line '{}', got {:?}",
            expected,
            line,
            findings.iter().map(|f| f.rule_id.clone()).collect::<Vec<_>>()
        );
    }
}

#[test]
fn test_hex_hash_content_is_suppressed() {
    let scanner = scanner();
    let hex64 = "4f7a9c2e8b1d6053ae7f2c9b4d8e1a6f3c0b7d2e5a8f1c4b9d6e3a0f7c2b5d8e";

    for line in [
        format!("sha256: {}", hex64),
        format!("integrity = \"sha512-{}\"", hex64),
        format!("md5sum {}", hex64),
        format!("checksum: {}", hex64),
    ] {
        let findings = scan_line(&scanner, &line, "app/build.py");
        assert!(
            findings.is_empty(),
            "hash context should suppress '{}', got {:?}",
            line,
            findings.iter().map(|f| f.rule_id.clone()).collect::<Vec<_>>()
        );
    }
}

#[test]
fn test_detect_secret_in_url_and_json() {
    let scanner = scanner();
    let token = "8fA7b9Xq2WpZ0kL9mJ1vN3cR8tY6uIo5E";
    let url_line = format!("fetch('https://api.vendor.com/v1/chat?api_key={}&lang=en');", token);
    let url_findings = scan_line(&scanner, &url_line, "src/urls.js");
    assert!(!url_findings.is_empty(), "secret inside URL must be detected");

    let json_line = format!("{{\"access_token\": \"{}\"}}", token);
    let json_findings = scan_line(&scanner, &json_line, "app/config.json");
    assert!(!json_findings.is_empty(), "secret inside JSON must be detected");
}

#[test]
fn test_preview_never_leaks_assignment_prefix() {
    let scanner = scanner();
    let line = "OPENAI_API_KEY=sk-proj-uR8xL9pQ2mK5vN4wZ7tY1sA0bC3dE6fG8hI0jK2lM4nP6qS8";
    let findings = scan_line(&scanner, line, "config/.env");

    assert!(!findings.is_empty());
    for finding in &findings {
        assert!(
            finding.secret_preview.starts_with("sk-pro"),
            "preview must contain only the secret value, got {}",
            finding.secret_preview
        );
        assert_eq!(findings.len(), 1, "one secret must produce exactly one finding");
    }
}

#[test]
fn test_ai_only_skips_generic_entropy() {
    let ai_only = Scanner::new(true, true, 4.5, 20);
    let line = "MY_TOKEN=qWe7AdF9gH2jK4lM6nP8rS0tU2vW4xY6aB8";
    let findings = scan_line(&ai_only, line, "app/service.py");

    assert!(
        findings.is_empty(),
        "ai-only mode must not report generic entropy tokens, got {:?}",
        findings.iter().map(|f| f.rule_id.clone()).collect::<Vec<_>>()
    );
}

#[test]
fn test_stripe_severity_policy() {
    let scanner = scanner();
    let live = format!("STRIPE_KEY=sk_live_{}", "51H8xQqP7w2Kd9Zv3Nt5Ra8Mb4Lc6Ye1U");
    let test = format!("STRIPE_KEY=sk_test_{}", "51H8xQqP7w2Kd9Zv3Nt5Ra8Mb4Lc6Ye1U");
    let publishable = format!("STRIPE_KEY=pk_live_{}", "51H8xQqP7w2Kd9Zv3Nt5Ra8Mb4Lc6Ye1U");

    let live_findings = scan_line(&scanner, &live, "app/pay.py");
    assert_eq!(live_findings[0].severity, Severity::Critical);
    assert!(live_findings[0].severity.rank() >= Severity::Low.rank());

    let test_findings = scan_line(&scanner, &test, "app/pay.py");
    assert_eq!(test_findings[0].severity, Severity::Low);

    let publishable_findings = scan_line(&scanner, &publishable, "app/pay.py");
    assert_eq!(publishable_findings[0].severity, Severity::Info);
    assert!(!publishable_findings[0].severity.rank() >= Severity::Low.rank());
}

#[test]
fn test_grouping_merges_occurrences_of_same_secret() {
    let scanner = scanner();
    let token = "8fA7b9Xq2WpZ0kL9mJ1vN3cR8tY6uIo5E";
    let line = format!("api_key={}", token);

    let mut findings = Vec::new();
    findings.extend(scanner.scan_line(&line, "app/first.py", 3, "aaaa1111", "Dev", "2026-01-01"));
    findings.extend(scanner.scan_line(&line, "app/second.py", 9, "bbbb2222", "Dev", "2026-02-01"));

    assert_eq!(findings.len(), 2);

    let groups = group_findings(&findings);
    assert_eq!(groups.len(), 1, "same secret must form a single group");
    assert_eq!(groups[0].occurrences.len(), 2);
    assert_eq!(groups[0].commit_count, 2);
    assert_eq!(groups[0].file_count, 2);
    assert_eq!(groups[0].first_seen, "2026-01-01");
    assert_eq!(groups[0].last_seen, "2026-02-01");
}

#[test]
fn test_fingerprint_is_stable_and_not_the_secret() {
    let token = "8fA7b9Xq2WpZ0kL9mJ1vN3cR8tY6uIo5E";
    let line = format!("api_key={}", token);
    let first = scan_line(&scanner(), &line, "app/a.py");
    let second = scan_line(&scanner(), &line, "app/b.py");

    assert_eq!(first[0].fingerprint, second[0].fingerprint);
    assert_eq!(first[0].fingerprint.len(), 16);
    assert!(!first[0].fingerprint.contains(token));
    assert!(!first[0].secret_preview.contains(token));
}

#[test]
fn test_context_scoring() {
    let high = evaluate_context("export OPENAI_API_KEY=\"val\"", "src/app.js", "val");
    assert_eq!(high, ContextScore::HighConfidence);

    let test_context = evaluate_context("const mock = \"some_token\";", "test/unit_test.py", "token");
    assert_eq!(test_context, ContextScore::FalsePositive);
}

#[test]
fn test_false_positive_filtering() {
    assert!(is_false_positive_token("example_key_here", false));
    assert!(is_false_positive_token("placeholder_secret_123456", false));
    assert!(is_false_positive_token("123e4567-e89b-12d3-a456-426614174000", false));
    assert!(is_false_positive_token("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", false));

    let sha256_of_empty = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    assert!(
        !is_false_positive_token(sha256_of_empty, false),
        "hex values are suppressed by context, not by shape"
    );
    assert!(is_false_positive_token(sha256_of_empty, true));
    assert!(has_hash_context("sha256 = \"abcd\""));
    assert!(!has_hash_context("api_key = \"abcd\""));
}

#[test]
fn test_shannon_entropy() {
    let low_entropy = "aaaaaaaaaaaaaaaaaaaa";
    let high_entropy = "8fA7b!9Xq2WpZ0kL9mJ1vN3cR8tY6uIo";

    assert!(calculate_shannon_entropy(low_entropy) < 1.0);
    assert!(calculate_shannon_entropy(high_entropy) > 4.5);
}

#[test]
fn test_candidate_families() {
    let hex = analyze_candidate("7b8f9e0a1c2d3e4f5a6b7c8d9e0f1a2b", 4.5, false);
    assert_eq!(hex.map(|c| c.family), Some(CandidateFamily::Hex));

    let base64 = analyze_candidate("8fA7b9Xq2WpZ0kL9mJ1vN3cR8tY6uIo5E-_", 4.5, false);
    assert_eq!(base64.map(|c| c.family), Some(CandidateFamily::Base64));

    let identifier = analyze_candidate("get_user_by_email_and_password", 4.5, false);
    assert!(identifier.is_none(), "long identifiers must not be treated as secrets");

    let dotted = analyze_candidate("index-D3F9a0b2c7d8e1f4a5b6c7d8e9f0a1b2.js", 4.5, false);
    assert!(dotted.is_none(), "file names must not be treated as secrets");

    let repeated = analyze_candidate("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 4.5, false);
    assert!(repeated.is_none());
}

#[test]
fn test_artifact_names_are_not_secrets() {
    let scanner = scanner();

    let workflow_line =
        "Compress-Archive -Path \"git-secret-hunter-$env:GITHUB_REF_NAME-windows-x64.zip\"";
    assert!(
        scan_line(&scanner, workflow_line, ".github/workflows/release.yml").is_empty(),
        "artifact file names must not be reported as secrets"
    );

    let bundle_line = "const bundle = \"vendor.min.js\"; const token = bundle;";
    assert!(
        scan_line(&scanner, bundle_line, "web/app.js").is_empty(),
        "minified bundle names must not be reported as secrets"
    );

    let version_line = "download_url = \"release-tool-1.2.3\"";
    assert!(
        scan_line(&scanner, version_line, "build/package.py").is_empty(),
        "version-like names must not be reported as secrets"
    );

    let secret_line =
        "service_token=Gh7Kd3Qp9Wz2Lm5Rt8Xy1Bv4Nc6Ej0Ai7Uo3Ps5Vd2Qf8Hk1Zr4.internal";
    assert!(
        !scan_line(&scanner, secret_line, "config/settings.py").is_empty(),
        "dotted tokens containing a real secret must still be detected"
    );
}

fn scan_file(
    scanner: &Scanner,
    lines: &[&str],
    path: &str,
) -> Vec<git_secret_hunter::scanner::Finding> {
    let numbered: Vec<(usize, &str)> = lines
        .iter()
        .enumerate()
        .map(|(index, line)| (index + 1, *line))
        .collect();

    scanner.scan_file_lines(&numbered, path, "a1b2c3d4e5", "Developer", "2026-01-01 10:00:00 +0000")
}

#[test]
fn test_multiline_yaml_block_secret() {
    let lines = [
        "service:",
        "  password: |",
        "    Gh7Kd3Qp9Wz2Lm5R",
        "    t8Xy1Bv4Nc6Ej0Ai7",
        "    Uo3Ps5Vd2Qf8Hk1Zr",
    ];

    let findings = scan_file(&scanner(), &lines, "config/deploy.yaml");

    assert!(
        findings.iter().any(|finding| finding.line_number == 3),
        "secret split across YAML block scalar lines must be detected, got {:?}",
        findings
            .iter()
            .map(|finding| (finding.rule_id.clone(), finding.line_number))
            .collect::<Vec<_>>()
    );
}

#[test]
fn test_multiline_toml_block_secret() {
    let lines = [
        "[service]",
        "api_token = \"\"\"",
        "Qw8Er9Ty2Ui4Op6As",
        "Hj3Kl5Zx7Cv9Bn1Mm",
        "\"\"\"",
    ];

    let findings = scan_file(&scanner(), &lines, "service/secrets.toml");

    assert!(
        findings.iter().any(|finding| finding.line_number == 3),
        "secret inside a TOML multi-line string must be detected, got {:?}",
        findings
            .iter()
            .map(|finding| (finding.rule_id.clone(), finding.line_number))
            .collect::<Vec<_>>()
    );
}

#[test]
fn test_pem_blocks_get_distinct_fingerprints() {
    let lines = [
        "-----BEGIN RSA PRIVATE KEY-----",
        "MIIEowIBAAKCAQEA7b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c",
        "MIIEowIBAAKCAQEA8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c",
        "-----END RSA PRIVATE KEY-----",
        "-----BEGIN EC PRIVATE KEY-----",
        "MHcCAQEEIN1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2",
        "MHcCAQEEIN2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3",
        "-----END EC PRIVATE KEY-----",
    ];

    let findings = scan_file(&scanner(), &lines, "certs/server.key");
    let material: Vec<&git_secret_hunter::scanner::Finding> = findings
        .iter()
        .filter(|finding| finding.rule_id == "private-key-material")
        .collect();

    assert_eq!(
        material.len(),
        2,
        "each PEM block must become one finding, got {:?}",
        findings
            .iter()
            .map(|finding| finding.rule_id.clone())
            .collect::<Vec<_>>()
    );

    assert_ne!(
        material[0].fingerprint, material[1].fingerprint,
        "different key bodies must not collapse into one fingerprint"
    );

    assert_eq!(material[0].line_number, 1);
    assert_eq!(material[1].line_number, 5);

    assert!(
        !findings.iter().any(|finding| finding.rule_id == "private-key"),
        "header-only findings must be replaced by full block findings"
    );
}

#[test]
fn test_checksum_manifest_lines_are_ignored() {
    let scanner = scanner();
    let manifest =
        "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08  release/app.tar.gz";

    assert!(
        scan_line(&scanner, manifest, "MANIFEST.sha256").is_empty(),
        "sha256sum-style manifest lines must not be reported"
    );

    let assigned = "API_KEY: 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";

    assert!(
        !scan_line(&scanner, assigned, "app/config.py").is_empty(),
        "a hex token assigned to a secret keyword must survive the checksum filter"
    );
}

#[test]
fn test_minified_bundles_skip_entropy_but_keep_rules() {
    let scanner = scanner();
    let pattern =
        "Aa0Bb1Cc2Dd3Ee4Ff5Gg6Hh7Ii8Jj9Kk0Ll1Mm2Nn3Oo4Pp5Qq6Rr7Ss8Tt9Uu0Vv1Ww2Xx3Yy4Zz5";
    let segment: String = pattern.repeat(3).chars().take(200).collect();
    let mut bundle = String::new();

    for index in 0..7 {
        bundle.push_str(&format!("var v{}='{}';", index, segment));
    }

    assert!(bundle.len() > 1200, "bundle len={}", bundle.len());

    let bundle_findings = scan_line(&scanner, &bundle, "static/bundle.js");

    assert!(
        bundle_findings
            .iter()
            .all(|finding| finding.rule_id != "high-entropy-token"),
        "entropy search must be disabled inside minified single-line bundles"
    );

    let control = scan_line(&scanner, &segment, "static/app.js");

    assert!(
        control
            .iter()
            .any(|finding| finding.rule_id == "high-entropy-token"),
        "the same value outside a minified line must still be detected"
    );

    let key_prefix = String::from("s") + "k-proj-";
    let key_line = format!("{}uR8xL9pQ2mK5vN4wZ7tY1sA0bC3dE6fG8hI0jK2lM4nP6qS8", key_prefix);
    let mut bundle_with_key = bundle.clone();
    bundle_with_key.push_str(&format!("var k='{}';", key_line));

    assert!(
        scan_line(&scanner, &bundle_with_key, "static/bundle.js")
            .iter()
            .any(|finding| finding.rule_id == "openai-api-key"),
        "provider rules must keep working inside minified bundles"
    );
}

#[test]
fn test_new_lockfiles_are_ignored() {
    use git_secret_hunter::scanner::filters::is_ignored_path;

    for path in [
        "uv.lock",
        "bun.lockb",
        "flake.lock",
        "mix.lock",
        "gradle.lockfile",
        ".terraform.lock.hcl",
        "packages.lock.json",
    ] {
        assert!(is_ignored_path(path), "{} must be ignored", path);
    }
}

#[test]
fn test_pem_markers_in_source_code_are_not_key_material() {
    let code = [
        "if !header.contains(\"-----BEGIN \") || !header.contains(\"PRIVATE KEY\") {",
        "    return None;",
        "}",
    ];

    let findings = scan_file(&scanner(), &code, "src/pem.rs");

    assert!(
        findings
            .iter()
            .all(|finding| finding.rule_id != "private-key-material"),
        "source code mentioning PEM markers must not be treated as key material, got {:?}",
        findings
            .iter()
            .map(|finding| finding.rule_id.clone())
            .collect::<Vec<_>>()
    );

    let unterminated = [
        "-----BEGIN RSA PRIVATE KEY-----",
        "MIIEowIBAAKCAQEA7b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c",
    ];

    let findings = scan_file(&scanner(), &unterminated, "certs/broken.key");

    assert!(
        findings
            .iter()
            .all(|finding| finding.rule_id != "private-key-material"),
        "a PEM block without an END marker must not produce key material"
    );
}

#[test]
fn test_verification_mode_captures_raw_secrets() {
    let capturing = Scanner::new(false, true, 4.5, 20).with_verification(true);
    let prefix = String::from("s") + "k-proj-";
    let line = format!("OPENAI_API_KEY={}uR8xL9pQ2mK5vN4wZ7tY1sA0bC3dE6fG8hI0jK2lM4nP6qS8", prefix);

    let findings = scan_line(&capturing, &line, ".env");

    assert!(findings.iter().any(|finding| finding.secret.is_some()));

    let plain = scan_line(&scanner(), &line, ".env");

    assert!(
        plain.iter().all(|finding| finding.secret.is_none()),
        "raw secrets must only be kept in memory when verification is enabled"
    );
}
