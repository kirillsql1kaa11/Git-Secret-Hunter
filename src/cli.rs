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
    version = env!("CARGO_PKG_VERSION"),
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

    #[arg(long, default_value_t = 8192, value_name = "CHARS")]
    pub max_line_len: usize,

    #[arg(long, default_value_t = 8 * 1024 * 1024, value_name = "BYTES")]
    pub max_file_size: usize,

    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    pub format: OutputFormat,

    #[arg(long)]
    pub max_commits: Option<usize>,

    #[arg(long)]
    pub staged: bool,

    #[arg(long, help = "Check found keys against the provider API (opt-in)")]
    pub verify: bool,

    #[arg(long, help = "Also scan initialized submodules")]
    pub submodules: bool,

    #[arg(long, help = "Also scan git notes")]
    pub notes: bool,

    #[arg(long, help = "Also scan local Git LFS objects")]
    pub lfs: bool,

    #[arg(long, value_name = "DATE", help = "Only commits after this date")]
    pub since: Option<String>,

    #[arg(long, value_name = "DATE", help = "Only commits before this date")]
    pub until: Option<String>,

    #[arg(long = "range", value_name = "REV..REV", help = "Only commits in this revision range")]
    pub rev_range: Option<String>,

    #[arg(long, help = "Only scan commits added since the last recorded scan of this repository")]
    pub incremental: bool,

    #[arg(long)]
    pub crawl: bool,

    #[arg(long, default_value_t = 100)]
    pub crawl_limit: usize,

    #[arg(long, default_value_t = 10)]
    pub crawl_depth: usize,

    #[arg(long, default_value_t = 4, value_name = "N")]
    pub crawl_concurrency: usize,

    #[arg(long)]
    pub github_token: Option<String>,

    #[arg(long)]
    pub query: Option<String>,

    #[arg(long, default_value_t = 0, value_name = "N")]
    pub min_stars: u32,

    #[arg(long, value_name = "MB")]
    pub max_size_mb: Option<u64>,

    #[arg(long, value_name = "LANG")]
    pub language: Option<String>,

    #[arg(long, default_value_t = 0, value_name = "N")]
    pub pushed_days: u32,

    #[arg(long)]
    pub include_forks: bool,

    #[arg(long)]
    pub include_archived: bool,

    #[arg(long, help = "Do not skip repositories scanned by previous runs")]
    pub no_crawl_dedupe: bool,

    #[arg(long)]
    pub tui: bool,
}
