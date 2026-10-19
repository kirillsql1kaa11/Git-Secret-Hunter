use git_secret_hunter::crawler::github::{build_search_query, matches_filters, CrawlFilters, GitHubRepo};
use git_secret_hunter::crawler::state::CrawlSeen;
use git_secret_hunter::verify::{
    is_verifiable, merge_verification, provider_for, Verification, VerificationStatus,
};

fn repo_template() -> GitHubRepo {
    GitHubRepo {
        id: 1,
        name: "sample".to_string(),
        full_name: "acme/sample".to_string(),
        html_url: "https://github.com/acme/sample".to_string(),
        description: None,
        fork: false,
        archived: false,
        stargazers_count: 10,
        size: 2048,
        language: Some("Python".to_string()),
        pushed_at: Some("2999-01-01T00:00:00Z".to_string()),
    }
}

#[test]
fn test_query_builder_includes_filters() {
    let filters = CrawlFilters {
        min_stars: 25,
        max_size_kb: Some(4096),
        language: Some("Rust".to_string()),
        include_forks: false,
        include_archived: false,
        pushed_days: None,
    };

    let query = build_search_query(Some("llm proxy"), &filters);

    assert!(query.contains("llm proxy"));
    assert!(query.contains("fork:false"));
    assert!(query.contains("archived:false"));
    assert!(query.contains("stars:>=25"));
    assert!(query.contains("size:<=4096"));
    assert!(query.contains("language:Rust"));
    assert!(!query.contains("pushed:"));

    let open = CrawlFilters {
        include_forks: true,
        include_archived: true,
        min_stars: 0,
        max_size_kb: None,
        pushed_days: Some(30),
        ..filters
    };

    let query = build_search_query(None, &open);

    assert!(!query.contains("fork:false"));
    assert!(!query.contains("archived:false"));
    assert!(!query.contains("stars:"));
    assert!(!query.contains("size:"));
    assert!(query.contains("pushed:>="));
}

#[test]
fn test_local_filter_matching() {
    let repo = repo_template();
    let permissive = CrawlFilters {
        min_stars: 0,
        max_size_kb: None,
        language: None,
        include_forks: true,
        include_archived: true,
        pushed_days: None,
    };

    assert!(matches_filters(&repo, &permissive));

    let no_forks = CrawlFilters {
        include_forks: false,
        ..permissive.clone()
    };
    let forked = GitHubRepo {
        fork: true,
        ..repo.clone()
    };
    assert!(!matches_filters(&forked, &no_forks));
    assert!(matches_filters(&repo, &no_forks));

    let strict = CrawlFilters {
        include_forks: false,
        include_archived: false,
        ..permissive.clone()
    };
    let archived = GitHubRepo {
        archived: true,
        ..repo.clone()
    };
    assert!(!matches_filters(&archived, &strict));

    let stars = CrawlFilters {
        min_stars: 100,
        ..permissive.clone()
    };
    assert!(!matches_filters(&repo, &stars));

    let language = CrawlFilters {
        language: Some("rust".to_string()),
        ..permissive.clone()
    };
    assert!(!matches_filters(&repo, &language));

    let recent = CrawlFilters {
        pushed_days: Some(30),
        ..permissive.clone()
    };
    assert!(matches_filters(&repo, &recent));

    let stale = GitHubRepo {
        pushed_at: Some("1999-01-01T00:00:00Z".to_string()),
        ..repo.clone()
    };
    assert!(!matches_filters(&stale, &recent));

    let oversized = GitHubRepo {
        size: 100 * 1024 * 1024,
        ..repo.clone()
    };
    let size_limit = CrawlFilters {
        max_size_kb: Some(1024),
        ..permissive
    };
    assert!(!matches_filters(&oversized, &size_limit));
}

#[test]
fn test_crawl_seen_state_roundtrip() {
    let path = std::env::temp_dir().join(format!("gsh-crawl-seen-{}.json", std::process::id()));
    let _ = std::fs::remove_file(&path);

    let mut seen = CrawlSeen::at_path(path.clone());

    assert!(!seen.contains("acme/sample"));

    seen.record("acme/sample");
    seen.save();

    let reloaded = CrawlSeen::at_path(path.clone());

    assert!(reloaded.contains("acme/sample"));
    assert_eq!(reloaded.len(), 1);
    assert!(reloaded.as_set().contains("acme/sample"));

    let _ = std::fs::remove_file(&path);
}

#[test]
fn test_verification_helpers() {
    assert!(is_verifiable("openai-api-key"));
    assert!(is_verifiable("github-pat"));
    assert!(is_verifiable("stripe-live-key"));
    assert!(!is_verifiable("high-entropy-token"));
    assert!(!is_verifiable("hex-secret-64"));

    assert_eq!(provider_for("github-pat"), Some("GitHub"));
    assert_eq!(provider_for("openai-api-key"), Some("OpenAI"));
    assert_eq!(provider_for("unknown-rule"), None);

    let invalid = Verification {
        status: VerificationStatus::Invalid,
        provider: "OpenAI".to_string(),
        detail: "HTTP 401".to_string(),
    };
    let verified = Verification {
        status: VerificationStatus::Verified,
        provider: "OpenAI".to_string(),
        detail: "HTTP 200".to_string(),
    };

    let merged = merge_verification(Some(&invalid), Some(&verified)).expect("merged");

    assert_eq!(merged.status, VerificationStatus::Verified);
    assert_eq!(
        merge_verification(Some(&invalid), None).expect("kept").status,
        VerificationStatus::Invalid
    );
    assert_eq!(
        merge_verification(None, Some(&verified)).expect("kept").status,
        VerificationStatus::Verified
    );
    assert!(merge_verification(None, None).is_none());
}
