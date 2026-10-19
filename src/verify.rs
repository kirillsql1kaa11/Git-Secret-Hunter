use crate::scanner::Finding;
use rayon::prelude::*;
use reqwest::blocking::Client;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue, AUTHORIZATION};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::OnceLock;
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum VerificationStatus {
    Verified,
    Invalid,
    Unknown,
    Error,
}

impl VerificationStatus {
    pub fn label(&self) -> &'static str {
        match self {
            VerificationStatus::Verified => "verified",
            VerificationStatus::Invalid => "invalid",
            VerificationStatus::Unknown => "unknown",
            VerificationStatus::Error => "error",
        }
    }

    pub fn rank(&self) -> u8 {
        match self {
            VerificationStatus::Verified => 4,
            VerificationStatus::Unknown => 2,
            VerificationStatus::Error => 1,
            VerificationStatus::Invalid => 0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Verification {
    pub status: VerificationStatus,
    pub provider: String,
    pub detail: String,
}

impl Verification {
    pub fn label(&self) -> String {
        format!("{}: {}", self.provider, self.status.label())
    }
}

pub fn merge_verification(
    current: Option<&Verification>,
    candidate: Option<&Verification>,
) -> Option<Verification> {
    match (current, candidate) {
        (Some(current), Some(candidate)) => {
            if candidate.status.rank() > current.status.rank() {
                Some(candidate.clone())
            } else {
                Some(current.clone())
            }
        }
        (Some(current), None) => Some(current.clone()),
        (None, Some(candidate)) => Some(candidate.clone()),
        (None, None) => None,
    }
}

#[derive(Clone, Copy)]
enum Auth {
    Bearer,
    Header(&'static str),
    Query(&'static str),
}

struct ProviderSpec {
    provider: &'static str,
    url: &'static str,
    auth: Auth,
    post: bool,
    extra_headers: &'static [(&'static str, &'static str)],
}

fn spec_for(rule_id: &str) -> Option<ProviderSpec> {
    let spec = match rule_id {
        "openai-api-key" => ProviderSpec {
            provider: "OpenAI",
            url: "https://api.openai.com/v1/models",
            auth: Auth::Bearer,
            post: false,
            extra_headers: &[],
        },
        "anthropic-api-key" => ProviderSpec {
            provider: "Anthropic",
            url: "https://api.anthropic.com/v1/models",
            auth: Auth::Header("x-api-key"),
            post: false,
            extra_headers: &[("anthropic-version", "2023-06-01")],
        },
        "gemini-api-key" => ProviderSpec {
            provider: "Google Gemini",
            url: "https://generativelanguage.googleapis.com/v1beta/models",
            auth: Auth::Query("key"),
            post: false,
            extra_headers: &[],
        },
        "deepseek-api-key" => ProviderSpec {
            provider: "DeepSeek",
            url: "https://api.deepseek.com/models",
            auth: Auth::Bearer,
            post: false,
            extra_headers: &[],
        },
        "huggingface-token" => ProviderSpec {
            provider: "Hugging Face",
            url: "https://huggingface.co/api/whoami-v2",
            auth: Auth::Bearer,
            post: false,
            extra_headers: &[],
        },
        "replicate-api-token" => ProviderSpec {
            provider: "Replicate",
            url: "https://api.replicate.com/v1/account",
            auth: Auth::Bearer,
            post: false,
            extra_headers: &[],
        },
        "groq-api-key" => ProviderSpec {
            provider: "Groq",
            url: "https://api.groq.com/openai/v1/models",
            auth: Auth::Bearer,
            post: false,
            extra_headers: &[],
        },
        "openrouter-api-key" => ProviderSpec {
            provider: "OpenRouter",
            url: "https://openrouter.ai/api/v1/key",
            auth: Auth::Bearer,
            post: false,
            extra_headers: &[],
        },
        "github-pat" => ProviderSpec {
            provider: "GitHub",
            url: "https://api.github.com/user",
            auth: Auth::Bearer,
            post: false,
            extra_headers: &[],
        },
        "gitlab-pat" => ProviderSpec {
            provider: "GitLab",
            url: "https://gitlab.com/api/v4/user",
            auth: Auth::Header("PRIVATE-TOKEN"),
            post: false,
            extra_headers: &[],
        },
        "slack-token" => ProviderSpec {
            provider: "Slack",
            url: "https://slack.com/api/auth.test",
            auth: Auth::Bearer,
            post: true,
            extra_headers: &[],
        },
        "stripe-live-key" | "stripe-test-key" => ProviderSpec {
            provider: "Stripe",
            url: "https://api.stripe.com/v1/balance",
            auth: Auth::Bearer,
            post: false,
            extra_headers: &[],
        },
        _ => return None,
    };

    Some(spec)
}

pub fn provider_for(rule_id: &str) -> Option<&'static str> {
    spec_for(rule_id).map(|spec| spec.provider)
}

pub fn is_verifiable(rule_id: &str) -> bool {
    spec_for(rule_id).is_some()
}

fn client() -> Option<&'static Client> {
    static CLIENT: OnceLock<Option<Client>> = OnceLock::new();

    CLIENT
        .get_or_init(|| {
            Client::builder()
                .timeout(Duration::from_secs(8))
                .user_agent("GitSecretHunter-Verifier/1.0")
                .build()
                .ok()
        })
        .as_ref()
}

pub fn verify_secret(rule_id: &str, secret: &str) -> Option<Verification> {
    let spec = spec_for(rule_id)?;

    let Some(client) = client() else {
        return Some(Verification {
            status: VerificationStatus::Error,
            provider: spec.provider.to_string(),
            detail: "http client unavailable".to_string(),
        });
    };

    let mut request = if spec.post {
        client.post(spec.url)
    } else {
        client.get(spec.url)
    };

    let mut headers = HeaderMap::new();

    match spec.auth {
        Auth::Bearer => {
            let Ok(value) = HeaderValue::from_str(&format!("Bearer {}", secret)) else {
                return Some(Verification {
                    status: VerificationStatus::Invalid,
                    provider: spec.provider.to_string(),
                    detail: "token cannot be sent as a header".to_string(),
                });
            };

            headers.insert(AUTHORIZATION, value);
        }
        Auth::Header(name) => {
            let Ok(value) = HeaderValue::from_str(secret) else {
                return Some(Verification {
                    status: VerificationStatus::Invalid,
                    provider: spec.provider.to_string(),
                    detail: "token cannot be sent as a header".to_string(),
                });
            };

            headers.insert(HeaderName::from_static(name), value);
        }
        Auth::Query(param) => {
            request = request.query(&[(param, secret)]);
        }
    }

    for (name, value) in spec.extra_headers {
        headers.insert(HeaderName::from_static(name), HeaderValue::from_static(value));
    }

    if !headers.is_empty() {
        request = request.headers(headers);
    }

    match request.send() {
        Ok(response) => {
            let status = response.status().as_u16();
            let body = response.text().unwrap_or_default();
            let (verification_status, detail) = classify(spec.provider, status, &body);

            Some(Verification {
                status: verification_status,
                provider: spec.provider.to_string(),
                detail,
            })
        }
        Err(error) => Some(Verification {
            status: VerificationStatus::Error,
            provider: spec.provider.to_string(),
            detail: error.to_string().chars().take(120).collect(),
        }),
    }
}

fn classify(provider: &str, http_status: u16, body: &str) -> (VerificationStatus, String) {
    if provider == "Slack" && body.contains("\"ok\":false") {
        return (VerificationStatus::Invalid, "HTTP 200, ok=false".to_string());
    }

    let body_lower = body.to_lowercase();

    match http_status {
        200..=299 => (VerificationStatus::Verified, format!("HTTP {}", http_status)),
        401 => (VerificationStatus::Invalid, "HTTP 401".to_string()),
        403 => {
            if body_lower.contains("bad credentials") || body_lower.contains("invalid") {
                (VerificationStatus::Invalid, "HTTP 403".to_string())
            } else {
                (
                    VerificationStatus::Unknown,
                    "HTTP 403 (access limit or permissions)".to_string(),
                )
            }
        }
        _ => (VerificationStatus::Unknown, format!("HTTP {}", http_status)),
    }
}

pub fn verify_findings(findings: &mut [Finding]) -> usize {
    let mut unique: HashMap<String, (String, String)> = HashMap::new();

    for finding in findings.iter() {
        let Some(secret) = &finding.secret else {
            continue;
        };

        if !is_verifiable(&finding.rule_id) {
            continue;
        }

        unique
            .entry(finding.fingerprint.clone())
            .or_insert_with(|| (finding.rule_id.clone(), secret.clone()));
    }

    if unique.is_empty() {
        return 0;
    }

    let entries: Vec<(String, String, String)> = unique
        .into_iter()
        .map(|(fingerprint, (rule_id, secret))| (fingerprint, rule_id, secret))
        .collect();

    let results: Vec<(String, Option<Verification>)> = entries
        .par_iter()
        .map(|(fingerprint, rule_id, secret)| {
            (
                fingerprint.clone(),
                verify_secret(rule_id, secret.as_str()),
            )
        })
        .collect();

    let verified: HashMap<String, Verification> = results
        .into_iter()
        .filter_map(|(fingerprint, verification)| {
            verification.map(|verification| (fingerprint, verification))
        })
        .collect();

    for finding in findings.iter_mut() {
        if let Some(verification) = verified.get(&finding.fingerprint) {
            finding.verification = Some(verification.clone());
        }
    }

    verified.len()
}
