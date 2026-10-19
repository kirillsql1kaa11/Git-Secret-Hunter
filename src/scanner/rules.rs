use regex::{Regex, RegexSet};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RuleCategory {
    ArtificialIntelligence,
    CloudProvider,
    VersionControl,
    Authentication,
    CryptographicKey,
    GenericEntropy,
}

impl RuleCategory {
    pub fn label(&self) -> &'static str {
        match self {
            RuleCategory::ArtificialIntelligence => "AI API Key",
            RuleCategory::CloudProvider => "Cloud Provider",
            RuleCategory::VersionControl => "VCS / Git Platform",
            RuleCategory::Authentication => "Auth Token",
            RuleCategory::CryptographicKey => "Private Key",
            RuleCategory::GenericEntropy => "High Entropy Secret",
        }
    }

    pub fn is_specific(&self) -> bool {
        !matches!(self, RuleCategory::GenericEntropy)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl Severity {
    pub fn label(&self) -> &'static str {
        match self {
            Severity::Critical => "CRITICAL",
            Severity::High => "HIGH",
            Severity::Medium => "MEDIUM",
            Severity::Low => "LOW",
            Severity::Info => "INFO",
        }
    }

    pub fn rank(&self) -> u8 {
        match self {
            Severity::Info => 0,
            Severity::Low => 1,
            Severity::Medium => 2,
            Severity::High => 3,
            Severity::Critical => 4,
        }
    }
}

pub struct DetectionRule {
    pub id: &'static str,
    pub name: &'static str,
    pub category: RuleCategory,
    pub severity: Severity,
    pub suppress_in_hash_context: bool,
    pub regex: Regex,
}

pub struct RuleRegistry {
    pub rules: Vec<DetectionRule>,
    pub rule_set: RegexSet,
}

impl RuleRegistry {
    pub fn new(ai_only: bool) -> Self {
        let mut rules = Vec::new();

        rules.push(DetectionRule {
            id: "openai-api-key",
            name: "OpenAI API Key",
            category: RuleCategory::ArtificialIntelligence,
            severity: Severity::Critical,
            suppress_in_hash_context: false,
            regex: Regex::new(r"\bsk-(?:(?:proj-|admin-|svcacct-)[A-Za-z0-9_-]{32,}|[A-Za-z0-9]{48})\b").unwrap(),
        });

        rules.push(DetectionRule {
            id: "anthropic-api-key",
            name: "Anthropic Claude API Key",
            category: RuleCategory::ArtificialIntelligence,
            severity: Severity::Critical,
            suppress_in_hash_context: false,
            regex: Regex::new(r"\bsk-ant-(?:api03|admin01)-[A-Za-z0-9_-]{80,}\b").unwrap(),
        });

        rules.push(DetectionRule {
            id: "gemini-api-key",
            name: "Google Gemini / AI Studio Key",
            category: RuleCategory::ArtificialIntelligence,
            severity: Severity::Critical,
            suppress_in_hash_context: false,
            regex: Regex::new(r"\bAIzaSy[A-Za-z0-9_-]{33}\b").unwrap(),
        });

        rules.push(DetectionRule {
            id: "deepseek-api-key",
            name: "DeepSeek API Key",
            category: RuleCategory::ArtificialIntelligence,
            severity: Severity::Critical,
            suppress_in_hash_context: false,
            regex: Regex::new(r"\bsk-[a-f0-9]{32}\b").unwrap(),
        });

        rules.push(DetectionRule {
            id: "huggingface-token",
            name: "Hugging Face User Access Token",
            category: RuleCategory::ArtificialIntelligence,
            severity: Severity::Critical,
            suppress_in_hash_context: false,
            regex: Regex::new(r"\bhf_[A-Za-z0-9]{34}\b").unwrap(),
        });

        rules.push(DetectionRule {
            id: "replicate-api-token",
            name: "Replicate API Token",
            category: RuleCategory::ArtificialIntelligence,
            severity: Severity::Critical,
            suppress_in_hash_context: false,
            regex: Regex::new(r"\br8_[A-Za-z0-9]{40}\b").unwrap(),
        });

        rules.push(DetectionRule {
            id: "groq-api-key",
            name: "Groq Cloud API Key",
            category: RuleCategory::ArtificialIntelligence,
            severity: Severity::Critical,
            suppress_in_hash_context: false,
            regex: Regex::new(r"\bgsk_[A-Za-z0-9]{52}\b").unwrap(),
        });

        rules.push(DetectionRule {
            id: "openrouter-api-key",
            name: "OpenRouter API Key",
            category: RuleCategory::ArtificialIntelligence,
            severity: Severity::Critical,
            suppress_in_hash_context: false,
            regex: Regex::new(r"\bsk-or-v1-[A-Za-z0-9]{64}\b").unwrap(),
        });

        rules.push(DetectionRule {
            id: "perplexity-api-key",
            name: "Perplexity AI API Key",
            category: RuleCategory::ArtificialIntelligence,
            severity: Severity::Critical,
            suppress_in_hash_context: false,
            regex: Regex::new(r"\bpplx-[A-Za-z0-9]{48}\b").unwrap(),
        });

        rules.push(DetectionRule {
            id: "cohere-api-key",
            name: "Cohere AI API Key",
            category: RuleCategory::ArtificialIntelligence,
            severity: Severity::Critical,
            suppress_in_hash_context: false,
            regex: Regex::new(r#"(?i)\bcohere[a-z0-9_]*\s*[:=]\s*['"][A-Za-z0-9]{40}['"]"#).unwrap(),
        });

        rules.push(DetectionRule {
            id: "mistral-api-key",
            name: "Mistral AI API Key",
            category: RuleCategory::ArtificialIntelligence,
            severity: Severity::Critical,
            suppress_in_hash_context: false,
            regex: Regex::new(r#"(?i)\bmistral[a-z0-9_]*\s*[:=]\s*['"][A-Za-z0-9]{32}['"]"#).unwrap(),
        });

        rules.push(DetectionRule {
            id: "together-api-key",
            name: "Together AI API Key",
            category: RuleCategory::ArtificialIntelligence,
            severity: Severity::Critical,
            suppress_in_hash_context: false,
            regex: Regex::new(r#"(?i)\btogether[a-z0-9_]*\s*[:=]\s*['"][a-f0-9]{64}['"]"#).unwrap(),
        });

        if !ai_only {
            rules.push(DetectionRule {
                id: "aws-access-key-id",
                name: "AWS Access Key ID",
                category: RuleCategory::CloudProvider,
                severity: Severity::Critical,
                suppress_in_hash_context: false,
                regex: Regex::new(r"\b(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}\b").unwrap(),
            });

            rules.push(DetectionRule {
                id: "github-pat",
                name: "GitHub Personal Access Token",
                category: RuleCategory::VersionControl,
                severity: Severity::Critical,
                suppress_in_hash_context: false,
                regex: Regex::new(r"\b(ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}|gho_[A-Za-z0-9]{36}|ghs_[A-Za-z0-9]{36})\b").unwrap(),
            });

            rules.push(DetectionRule {
                id: "gitlab-pat",
                name: "GitLab Personal Access Token",
                category: RuleCategory::VersionControl,
                severity: Severity::Critical,
                suppress_in_hash_context: false,
                regex: Regex::new(r"\bglpat-[A-Za-z0-9_\-]{20}\b").unwrap(),
            });

            rules.push(DetectionRule {
                id: "jwt-token",
                name: "JSON Web Token (JWT)",
                category: RuleCategory::Authentication,
                severity: Severity::High,
                suppress_in_hash_context: false,
                regex: Regex::new(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b").unwrap(),
            });

            rules.push(DetectionRule {
                id: "private-key",
                name: "Private Cryptographic Key",
                category: RuleCategory::CryptographicKey,
                severity: Severity::Critical,
                suppress_in_hash_context: false,
                regex: Regex::new(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----").unwrap(),
            });

            rules.push(DetectionRule {
                id: "slack-token",
                name: "Slack API / Bot Token",
                category: RuleCategory::Authentication,
                severity: Severity::High,
                suppress_in_hash_context: false,
                regex: Regex::new(r"\bxox[baprs]-[0-9]{10,13}-[0-9]{10,13}[A-Za-z0-9-]*\b").unwrap(),
            });

            rules.push(DetectionRule {
                id: "stripe-live-key",
                name: "Stripe Live Secret Key",
                category: RuleCategory::CloudProvider,
                severity: Severity::Critical,
                suppress_in_hash_context: false,
                regex: Regex::new(r"\b(?:sk|rk)_live_[0-9a-zA-Z]{24,}\b").unwrap(),
            });

            rules.push(DetectionRule {
                id: "stripe-test-key",
                name: "Stripe Test Key (non-production)",
                category: RuleCategory::CloudProvider,
                severity: Severity::Low,
                suppress_in_hash_context: false,
                regex: Regex::new(r"\b(?:sk|rk)_test_[0-9a-zA-Z]{24,}\b").unwrap(),
            });

            rules.push(DetectionRule {
                id: "stripe-publishable-key",
                name: "Stripe Publishable Key (public by design)",
                category: RuleCategory::CloudProvider,
                severity: Severity::Info,
                suppress_in_hash_context: false,
                regex: Regex::new(r"\bpk_(?:live|test)_[0-9a-zA-Z]{24,}\b").unwrap(),
            });

            rules.push(DetectionRule {
                id: "hex-secret-32",
                name: "Hex-Encoded Secret (32 chars)",
                category: RuleCategory::GenericEntropy,
                severity: Severity::Medium,
                suppress_in_hash_context: true,
                regex: Regex::new(r"\b[0-9a-fA-F]{32}\b").unwrap(),
            });

            rules.push(DetectionRule {
                id: "hex-secret-40",
                name: "Hex-Encoded Secret (40 chars)",
                category: RuleCategory::GenericEntropy,
                severity: Severity::Medium,
                suppress_in_hash_context: true,
                regex: Regex::new(r"\b[0-9a-fA-F]{40}\b").unwrap(),
            });

            rules.push(DetectionRule {
                id: "hex-secret-64",
                name: "Hex-Encoded Secret (64 chars)",
                category: RuleCategory::GenericEntropy,
                severity: Severity::High,
                suppress_in_hash_context: true,
                regex: Regex::new(r"\b[0-9a-fA-F]{64}\b").unwrap(),
            });
        }

        let rule_set = RegexSet::new(rules.iter().map(|rule| rule.regex.as_str()))
            .expect("rule patterns are valid");

        Self { rules, rule_set }
    }

    pub fn matching_indices(&self, line: &str) -> Vec<usize> {
        self.rule_set.matches(line).iter().collect()
    }

    pub fn find_by_id(&self, id: &str) -> Option<&DetectionRule> {
        self.rules.iter().find(|rule| rule.id == id)
    }
}
