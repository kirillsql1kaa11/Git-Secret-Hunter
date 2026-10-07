use clap::{Parser, ValueEnum};
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum OutputFormat {
    Text,
    Json,
}

#[derive(Parser, Debug, Clone)]
#[command(
    name = "git-secret-hunter",
    author = "kira0",
    version = "0.1.0",
    about = "Blazing fast Git history secret scanner & AI API key auditor"
)]
pub struct Cli {
    #[arg(short, long, default_value = ".")]
    pub path: PathBuf,

    #[arg(long)]
    pub ai_only: bool,

    #[arg(long, default_value_t = true)]
    pub include_dangling: bool,

    #[arg(long, default_value_t = false)]
    pub no_entropy: bool,

    #[arg(long, default_value_t = 4.5)]
    pub entropy_threshold: f64,

    #[arg(long, default_value_t = 24)]
    pub min_entropy_len: usize,

    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    pub format: OutputFormat,

    #[arg(long)]
    pub max_commits: Option<usize>,

    #[arg(long)]
    pub staged: bool,

    #[arg(long)]
    pub crawl: bool,

    #[arg(long, default_value_t = 100)]
    pub crawl_limit: usize,

    #[arg(long, default_value_t = 10)]
    pub crawl_depth: usize,

    #[arg(long)]
    pub github_token: Option<String>,

    #[arg(long)]
    pub query: Option<String>,

    #[arg(long)]
    pub tui: bool,
}
