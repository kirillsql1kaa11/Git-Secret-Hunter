#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use git_secret_hunter::gui::launch as launch_gui;
use git_secret_hunter::gui::scan::{ScanOptions, run_scan};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;

#[derive(Clone, Default)]
struct GuiCli {
    path: Option<PathBuf>,
    out: Option<PathBuf>,
    selftest: bool,
    ai_only: bool,
    no_entropy: bool,
    staged: bool,
    no_dangling: bool,
}

impl GuiCli {
    fn parse() -> Self {
        let mut cli = Self {
            no_dangling: false,
            ..Self::default()
        };

        let mut args = std::env::args().skip(1);

        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--selftest" => cli.selftest = true,
                "--ai-only" => cli.ai_only = true,
                "--no-entropy" => cli.no_entropy = true,
                "--staged" => cli.staged = true,
                "--no-dangling" => cli.no_dangling = true,
                "-p" | "--path" => cli.path = args.next().map(PathBuf::from),
                "--out" => cli.out = args.next().map(PathBuf::from),
                "-h" | "--help" => {
                    print_help();
                    std::process::exit(0);
                }
                _ => {}
            }
        }

        cli
    }

    fn to_options(&self) -> ScanOptions {
        let mut options = ScanOptions::default();

        if let Some(path) = &self.path {
            options.path = path.clone();
        }

        options.ai_only = self.ai_only;
        options.check_entropy = !self.no_entropy;
        options.include_dangling = !self.no_dangling;
        options.staged = self.staged;
        options
    }
}

fn print_help() {
    println!(
        "git-secret-hunter-gui [--path <REPO>] [--selftest] [--out <FILE>] [--ai-only] [--no-entropy] [--no-dangling] [--staged]\n\
         \n\
         Without --selftest the graphical window is opened.\n\
         With --selftest the scan runs headlessly and the JSON report is written to --out (or printed to stdout)."
    );
}

fn main() {
    let cli = GuiCli::parse();

    if cli.selftest {
        std::process::exit(run_selftest(&cli));
    }

    if let Err(error) = launch_gui(cli.path.clone(), None) {
        eprintln!("Не удалось запустить GUI: {}", error);
        std::process::exit(2);
    }
}

fn run_selftest(cli: &GuiCli) -> i32 {
    let options = cli.to_options();
    let progress = Arc::new(AtomicUsize::new(0));
    let total = Arc::new(AtomicUsize::new(0));

    match run_scan(&options, &progress, &total) {
        Ok(result) => {
            let json = result.to_json();

            match &cli.out {
                Some(out) => {
                    if std::fs::write(out, &json).is_err() {
                        eprintln!("Не удалось записать отчёт: {}", out.display());
                        return 2;
                    }
                }
                None => println!("{}", json),
            }

            if result.failing_groups() > 0 { 1 } else { 0 }
        }
        Err(error) => {
            match &cli.out {
                Some(out) => {
                    let escaped = error.replace('"', "'");
                    let _ = std::fs::write(out, format!("{{\"error\": \"{}\"}}", escaped));
                }
                None => eprintln!("{}", error),
            }

            2
        }
    }
}
