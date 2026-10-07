use git_secret_hunter::scanner::entropy::calculate_shannon_entropy;
use git_secret_hunter::scanner::filters::{evaluate_context, is_false_positive_token, ContextScore};
use git_secret_hunter::scanner::Scanner;

#[test]
fn test_detect_openai_key() {
    let scanner = Scanner::new(false, false, 4.5, 20);
    let prefix = String::from("s") + "k-proj-";
    let body = "uR8xL9pQ2mK5vN4wZ7tY1sA0bC3dE6fG8hI0jK2lM4nP6qS8";
    let sample_line = format!("const client = new OpenAI({{ apiKey: '{}{}' }});", prefix, body);
    let findings = scanner.scan_line(
        &sample_line,
        "src/ai.ts",
        15,
        "a1b2c3d4",
        "Developer",
        "2026-01-01",
    );

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_id, "openai-api-key");
}

#[test]
fn test_detect_anthropic_key() {
    let scanner = Scanner::new(false, false, 4.5, 20);
    let prefix = String::from("s") + "k-ant-api03-";
    let body = "xK9pL2mQ5vR8wZ1tY4sA7bC0dE3fG6hI9jK2lM5nP8qS1tU4vW7xY0zA3bC6dE9fG2hI5jK8lM1nP4qS7tU0vW3xY6zA9bC2dE5";
    let sample_line = format!("ANTHROPIC_API_KEY={}{}", prefix, body);
    let findings = scanner.scan_line(
        &sample_line,
        ".env",
        2,
        "b2c3d4e5",
        "Developer",
        "2026-01-01",
    );

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_id, "anthropic-api-key");
}

#[test]
fn test_detect_gemini_key() {
    let scanner = Scanner::new(false, false, 4.5, 20);
    let prefix = String::from("AI") + "zaSy";
    let body = "D9xK2pL5mQ8vR1wZ4tY7sA0bC3dE6fG8h";
    let sample_line = format!("export GEMINI_API_KEY=\"{}{}\"", prefix, body);
    let findings = scanner.scan_line(
        &sample_line,
        "deploy.sh",
        5,
        "c3d4e5f6",
        "Developer",
        "2026-01-01",
    );

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_id, "gemini-api-key");
}

#[test]
fn test_detect_deepseek_key() {
    let scanner = Scanner::new(false, false, 4.5, 20);
    let prefix = String::from("s") + "k-";
    let p1 = "7b8f9e0a1c2d3e4f";
    let p2 = "5a6b7c8d9e0f1a2b";
    let sample_line = format!("DEEPSEEK_API_KEY={}{}{}", prefix, p1, p2);
    let findings = scanner.scan_line(
        &sample_line,
        "config.env",
        3,
        "d1e2f3a4",
        "Developer",
        "2026-01-01",
    );

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_id, "deepseek-api-key");
}

#[test]
fn test_detect_huggingface_key() {
    let scanner = Scanner::new(false, false, 4.5, 20);
    let prefix = String::from("h") + "f_";
    let body = "uR8xL9pQ2mK5vN4wZ7tY1sA0bC3dE6fG8h";
    let sample_line = format!("token = \"{}{}\"", prefix, body);
    let findings = scanner.scan_line(
        &sample_line,
        "model.py",
        10,
        "d4e5f6a1",
        "Developer",
        "2026-01-01",
    );

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_id, "huggingface-token");
}

#[test]
fn test_detect_aws_key() {
    let scanner = Scanner::new(false, false, 4.5, 20);
    let prefix = String::from("AK") + "IA";
    let body = "IOSFODNN7QAZWSX9";
    let sample_line = format!("aws_access_key_id = {}{}", prefix, body);
    let findings = scanner.scan_line(
        &sample_line,
        "credentials",
        3,
        "e5f6a1b2",
        "Developer",
        "2026-01-01",
    );

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_id, "aws-access-key-id");
}

#[test]
fn test_detect_github_pat() {
    let scanner = Scanner::new(false, false, 4.5, 20);
    let prefix = String::from("gh") + "p_";
    let body = "9u8v7w6x5y4z3a2b1c0d9e8f7g6h5i4j3k2l";
    let sample_line = format!("GH_TOKEN={}{}", prefix, body);
    let findings = scanner.scan_line(
        &sample_line,
        ".github/workflows/ci.yml",
        22,
        "f6a1b2c3",
        "Developer",
        "2026-01-01",
    );

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_id, "github-pat");
}

#[test]
fn test_detect_private_key() {
    let scanner = Scanner::new(false, false, 4.5, 20);
    let prefix = String::from("-----BEGIN ") + "RSA PRIVATE KEY-----";
    let sample_line = prefix;
    let findings = scanner.scan_line(
        &sample_line,
        "certs/server.key",
        1,
        "a2b3c4d5",
        "Developer",
        "2026-01-01",
    );

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_id, "private-key");
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
    assert!(is_false_positive_token("example_key_here"));
    assert!(is_false_positive_token("placeholder_secret_123456"));
    assert!(is_false_positive_token("123e4567-e89b-12d3-a456-426614174000"));
    assert!(is_false_positive_token("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
}

#[test]
fn test_shannon_entropy() {
    let low_entropy = "aaaaaaaaaaaaaaaaaaaa";
    let high_entropy = "8fA7b!9Xq2WpZ0kL9mJ1vN3cR8tY6uIo";

    assert!(calculate_shannon_entropy(low_entropy) < 1.0);
    assert!(calculate_shannon_entropy(high_entropy) > 4.5);
}
