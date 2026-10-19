pub mod scan;

use crate::crawler::{
    CrawlEvent, CrawlHandle, CrawlOptions, CrawlTotals, CrawledRepo, crawl_report_json,
    spawn_crawl,
};
use crate::scanner::{FindingGroup, Severity};
use crate::tui::state::ResolvedState;
use crate::verify::VerificationStatus;
use eframe::egui;
use scan::{ScanHandle, ScanOptions, ScanOutcome, ScanResult, spawn_scan};
use std::path::PathBuf;

const MAX_LIST_TEXT: usize = 72;
const MAX_OCCURRENCES_SHOWN: usize = 200;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GuiMode {
    Crawler,
    Repository,
}

pub struct GuiApp {
    mode: GuiMode,
    options: ScanOptions,
    path_input: String,
    pending: Option<ScanHandle>,
    result: Option<ScanResult>,
    error: Option<String>,
    severity_enabled: [bool; 5],
    query: String,
    only_unresolved: bool,
    selected: Option<usize>,
    resolved: ResolvedState,
    export_status: Option<String>,
    crawl_options: CrawlOptions,
    crawl_query: String,
    crawl_token: String,
    crawl: Option<CrawlHandle>,
    crawl_total: usize,
    crawl_repos: Vec<CrawledRepo>,
    crawl_active: Vec<String>,
    crawl_failed: usize,
    crawl_totals: Option<CrawlTotals>,
    crawl_cancelled: bool,
    crawl_error: Option<String>,
    crawl_only_leaks: bool,
    crawl_filter: String,
    crawl_skipped_known: usize,
    crawl_language: String,
    range_input: String,
    since_input: String,
    until_input: String,
    selected_repo: Option<usize>,
    selected_crawl_group: Option<usize>,
}

impl GuiApp {
    pub fn new(
        initial_path: Option<PathBuf>,
        mut options: ScanOptions,
        creation: &eframe::CreationContext<'_>,
    ) -> Self {
        if let Some(path) = initial_path {
            options.path = path;
        }

        creation.egui_ctx.set_visuals(egui::Visuals::dark());

        let crawl_options = CrawlOptions::default();
        let crawl_token = crawl_options.token.clone().unwrap_or_default();
        let crawl_query = crawl_options.query.clone().unwrap_or_default();
        let crawl_language = crawl_options
            .filters
            .language
            .clone()
            .unwrap_or_default();

        Self {
            mode: GuiMode::Crawler,
            path_input: options.path.display().to_string(),
            options,
            pending: None,
            result: None,
            error: None,
            severity_enabled: [true; 5],
            query: String::new(),
            only_unresolved: false,
            selected: None,
            resolved: ResolvedState::load(),
            export_status: None,
            crawl_options,
            crawl_query,
            crawl_token,
            crawl: None,
            crawl_total: 0,
            crawl_repos: Vec::new(),
            crawl_active: Vec::new(),
            crawl_failed: 0,
            crawl_totals: None,
            crawl_cancelled: false,
            crawl_error: None,
            crawl_only_leaks: true,
            crawl_filter: String::new(),
            crawl_skipped_known: 0,
            crawl_language,
            range_input: String::new(),
            since_input: String::new(),
            until_input: String::new(),
            selected_repo: None,
            selected_crawl_group: None,
        }
    }

    fn poll_scan(&mut self, ctx: &egui::Context) {
        if self.pending.is_none() {
            return;
        }

        let event = self.pending.as_ref().and_then(|handle| handle.poll());

        match event {
            Some(ScanOutcome::Done(result)) => {
                self.selected = if result.groups.is_empty() { None } else { Some(0) };
                self.result = Some(*result);
                self.error = None;
                self.export_status = None;
                self.pending = None;
            }
            Some(ScanOutcome::Failed(error)) => {
                self.error = Some(error);
                self.pending = None;
            }
            None => ctx.request_repaint(),
        }
    }

    fn poll_crawl(&mut self, ctx: &egui::Context) {
        if self.crawl.is_none() {
            return;
        }

        let mut finished = false;

        while let Some(event) = self.crawl.as_ref().and_then(|handle| handle.poll()) {
            match event {
                CrawlEvent::Discovered {
                    total,
                    skipped_known,
                    ..
                } => {
                    self.crawl_total = total;
                    self.crawl_skipped_known = skipped_known;
                }
                CrawlEvent::Started { repo_name } => {
                    self.crawl_active.push(repo_name);
                }
                CrawlEvent::Scanned(repo) => {
                    self.crawl_active.retain(|name| name != &repo.repo_name);
                    self.crawl_repos.push(*repo);
                }
                CrawlEvent::Failed { repo_name } => {
                    self.crawl_active.retain(|name| name != &repo_name);
                    self.crawl_failed += 1;
                }
                CrawlEvent::Finished(totals) => {
                    self.crawl_active.clear();
                    self.crawl_total = totals.discovered;
                    self.crawl_repos.sort_by(|left, right| {
                        right
                            .failing_findings
                            .cmp(&left.failing_findings)
                            .then(right.groups.len().cmp(&left.groups.len()))
                            .then(left.repo_name.cmp(&right.repo_name))
                    });
                    self.selected_repo = self
                        .crawl_repos
                        .iter()
                        .position(|repo| !repo.groups.is_empty());
                    self.selected_crawl_group = Some(0);
                    self.crawl_totals = Some(*totals);
                    self.crawl = None;
                    finished = true;
                    break;
                }
                CrawlEvent::Error(error) => {
                    self.crawl_active.clear();
                    self.crawl_error = Some(error);
                    self.crawl = None;
                    finished = true;
                    break;
                }
            }
        }

        if !finished && self.crawl.is_some() {
            ctx.request_repaint();
        }
    }

    fn start_crawl(&mut self, ctx: &egui::Context) {
        if self.crawl.is_some() {
            return;
        }

        self.crawl_options.limit = self.crawl_options.limit.clamp(1, 500);
        self.crawl_options.depth = self.crawl_options.depth.clamp(1, 5000);
        self.crawl_options.concurrency = self.crawl_options.concurrency.clamp(1, 32);
        self.crawl_options.query = Some(self.crawl_query.trim().to_string());
        self.crawl_options.filters.language = {
            let language = self.crawl_language.trim().to_string();
            (!language.is_empty()).then_some(language)
        };
        self.crawl_options.token = {
            let token = self.crawl_token.trim().to_string();
            if token.is_empty() {
                std::env::var("GITHUB_TOKEN")
                    .ok()
                    .filter(|token| !token.trim().is_empty())
            } else {
                Some(token)
            }
        };

        self.crawl_repos.clear();
        self.crawl_active.clear();
        self.crawl_failed = 0;
        self.crawl_total = 0;
        self.crawl_skipped_known = 0;
        self.crawl_totals = None;
        self.crawl_error = None;
        self.crawl_cancelled = false;
        self.selected_repo = None;
        self.selected_crawl_group = None;
        self.export_status = None;

        let notify_ctx = ctx.clone();
        self.crawl = Some(spawn_crawl(self.crawl_options.clone(), move || {
            notify_ctx.request_repaint();
        }));
    }

    fn stop_crawl(&mut self) {
        if let Some(handle) = &self.crawl {
            handle.cancel();
            self.crawl_cancelled = true;
        }
    }

    fn start_scan(&mut self, ctx: &egui::Context) {
        if self.pending.is_some() {
            return;
        }

        let path = PathBuf::from(self.path_input.trim());

        if path.as_os_str().is_empty() {
            self.error = Some("Укажите путь к репозиторию".to_string());
            return;
        }

        if !path.exists() {
            self.error = Some(format!("Путь не найден: {}", path.display()));
            return;
        }

        self.options.path = path;
        self.options.rev_range = {
            let value = self.range_input.trim().to_string();
            (!value.is_empty()).then_some(value)
        };
        self.options.since = {
            let value = self.since_input.trim().to_string();
            (!value.is_empty()).then_some(value)
        };
        self.options.until = {
            let value = self.until_input.trim().to_string();
            (!value.is_empty()).then_some(value)
        };
        self.result = None;
        self.error = None;
        self.export_status = None;
        self.selected = None;

        let notify_ctx = ctx.clone();
        self.pending = Some(spawn_scan(self.options.clone(), move || {
            notify_ctx.request_repaint();
        }));
    }

    fn export_json(&mut self) {
        let payload = match self.mode {
            GuiMode::Repository => match &self.result {
                Some(result) => result.to_json(),
                None => return,
            },
            GuiMode::Crawler => match &self.crawl_totals {
                Some(totals) => crawl_report_json(&self.crawl_options, totals, &self.crawl_repos),
                None => return,
            },
        };

        let default_name = match self.mode {
            GuiMode::Repository => "secret-hunter-report.json".to_string(),
            GuiMode::Crawler => format!(
                "secret-hunter-crawl-{}.json",
                self.crawl_repos.len()
            ),
        };

        let Some(target) = rfd::FileDialog::new()
            .set_file_name(default_name)
            .add_filter("JSON", &["json"])
            .save_file()
        else {
            return;
        };

        match std::fs::write(&target, payload) {
            Ok(()) => self.export_status = Some(format!("Отчёт сохранён: {}", target.display())),
            Err(error) => self.export_status = Some(format!("Ошибка записи: {}", error)),
        }
    }

    fn visible_scan_indices(&self) -> Vec<usize> {
        let Some(result) = &self.result else {
            return Vec::new();
        };

        let query = self.query.trim().to_lowercase();

        result
            .groups
            .iter()
            .enumerate()
            .filter(|(_, group)| self.severity_enabled[group.severity.rank() as usize])
            .filter(|(_, group)| {
                !self.only_unresolved || !self.resolved.is_resolved(&group.fingerprint)
            })
            .filter(|(_, group)| {
                if query.is_empty() {
                    return true;
                }

                format!(
                    "{} {} {} {} {}",
                    group.rule_name,
                    group.category.label(),
                    group.secret_preview,
                    group.fingerprint,
                    group.files().join(" ")
                )
                .to_lowercase()
                .contains(&query)
            })
            .map(|(index, _)| index)
            .collect()
    }

    fn visible_crawl_indices(&self) -> Vec<usize> {
        let filter = self.crawl_filter.trim().to_lowercase();

        self.crawl_repos
            .iter()
            .enumerate()
            .filter(|(_, repo)| !self.crawl_only_leaks || !repo.groups.is_empty())
            .filter(|(_, repo)| {
                filter.is_empty() || repo.repo_name.to_lowercase().contains(&filter)
            })
            .map(|(index, _)| index)
            .collect()
    }

    fn toolbar(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        egui::Panel::top("toolbar").show(ui, |ui| {
            ui.add_space(6.0);

            ui.horizontal_wrapped(|ui| {
                ui.heading("Git Secret Hunter");
                ui.label(
                    egui::RichText::new("GUI")
                        .color(egui::Color32::from_rgb(120, 200, 255))
                        .strong(),
                );
                ui.separator();

                ui.selectable_value(
                    &mut self.mode,
                    GuiMode::Crawler,
                    "Краулер случайных репозиториев",
                );
                ui.selectable_value(&mut self.mode, GuiMode::Repository, "Локальный репозиторий");
            });

            ui.add_space(4.0);

            match self.mode {
                GuiMode::Crawler => self.toolbar_crawler(ui, ctx),
                GuiMode::Repository => self.toolbar_repository(ui, ctx),
            }

            if let Some(error) = &self.error {
                ui.add_space(2.0);
                ui.colored_label(egui::Color32::from_rgb(255, 100, 100), error.clone());
            }

            if let Some(error) = &self.crawl_error {
                ui.add_space(2.0);
                ui.colored_label(egui::Color32::from_rgb(255, 100, 100), error.clone());
            }

            ui.add_space(6.0);
        });
    }

    fn toolbar_crawler(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        let running = self.crawl.is_some();

        ui.horizontal_wrapped(|ui| {
            ui.label("Запрос:");
            ui.add(
                egui::TextEdit::singleline(&mut self.crawl_query)
                    .desired_width(230.0)
                    .hint_text("пусто = случайные репозитории"),
            );

            ui.separator();
            ui.label("Репозиториев:");
            ui.add(
                egui::DragValue::new(&mut self.crawl_options.limit)
                    .range(1..=500)
                    .speed(1.0),
            );

            ui.label("Глубина (коммитов):");
            ui.add(
                egui::DragValue::new(&mut self.crawl_options.depth)
                    .range(1..=5000)
                    .speed(5.0),
            );

            ui.label("Потоков:");
            ui.add(
                egui::DragValue::new(&mut self.crawl_options.concurrency)
                    .range(1..=32)
                    .speed(1.0),
            );

            ui.separator();
            ui.checkbox(&mut self.crawl_options.ai_only, "Только AI-ключи");
            ui.checkbox(&mut self.crawl_only_leaks, "Показывать только с находками");

            ui.separator();

            if ui
                .add_enabled(!running, egui::Button::new("Запустить краулинг"))
                .clicked()
            {
                self.start_crawl(ctx);
            }

            if ui
                .add_enabled(running, egui::Button::new("Остановить"))
                .clicked()
            {
                self.stop_crawl();
            }

            if ui
                .add_enabled(
                    self.crawl_totals.is_some() && !running,
                    egui::Button::new("Экспорт JSON…"),
                )
                .clicked()
            {
                self.export_json();
            }
        });

        ui.add_space(3.0);

        ui.horizontal_wrapped(|ui| {
            ui.label("GitHub-токен:");
            ui.add(
                egui::TextEdit::singleline(&mut self.crawl_token)
                    .desired_width(260.0)
                    .hint_text("необязательно, повышает лимиты API"),
            );

            ui.separator();

            if running {
                ui.spinner();

                let done = self.crawl_repos.len() + self.crawl_failed;
                let total = self.crawl_total.max(1);
                let fraction = (done as f32 / total as f32).clamp(0.0, 1.0);

                ui.add(
                    egui::ProgressBar::new(fraction)
                        .desired_width(200.0)
                        .show_percentage(),
                );

                let elapsed = self
                    .crawl
                    .as_ref()
                    .map(|handle| handle.started.elapsed().as_secs_f32())
                    .unwrap_or_default();

                ui.label(format!("{}/{} репозиториев, {:.0}s", done, total, elapsed));

                if self.crawl_cancelled {
                    ui.colored_label(egui::Color32::from_rgb(230, 190, 90), "останавливаю…");
                } else if !self.crawl_active.is_empty() {
                    let active = self
                        .crawl_active
                        .iter()
                        .take(3)
                        .cloned()
                        .collect::<Vec<_>>()
                        .join(", ");
                    ui.label(format!("сейчас: {}", active));
                }
            } else if let Some(totals) = &self.crawl_totals {
                ui.label(format!(
                    "Просканировано {} из {} (ошибок {}, пропущено {}), находок в {} репозиториях, время {:.1}s",
                    totals.scanned,
                    totals.discovered,
                    totals.failed,
                    totals.skipped,
                    totals.repos_with_leaks,
                    totals.duration.as_secs_f32()
                ));
            } else {
                ui.label(
                    egui::RichText::new(
                        "Случайные репозитории GitHub сканируются параллельно; результаты появляются по мере готовности.",
                    )
                    .color(egui::Color32::from_gray(150)),
                );
            }
        });

        ui.add_space(3.0);

        egui::CollapsingHeader::new("Фильтры выборки и проверка ключей")
            .default_open(false)
            .show(ui, |ui| {
                egui::Grid::new("crawl-filters")
                    .num_columns(2)
                    .spacing([14.0, 6.0])
                    .show(ui, |ui| {
                        ui.label("Язык:");
                        ui.add(
                            egui::TextEdit::singleline(&mut self.crawl_language)
                                .desired_width(140.0)
                                .hint_text("python"),
                        );
                        ui.end_row();

                        ui.label("Минимум звёзд:");
                        ui.add(
                            egui::DragValue::new(&mut self.crawl_options.filters.min_stars)
                                .range(0..=100_000),
                        );
                        ui.end_row();

                        ui.label("Максимальный размер:");
                        ui.horizontal(|ui| {
                            let mut limited = self.crawl_options.filters.max_size_kb.is_some();

                            if ui.checkbox(&mut limited, "ограничить").changed() {
                                self.crawl_options.filters.max_size_kb =
                                    limited.then_some(500 * 1024);
                            }

                            let mut megabytes = self.crawl_options.filters.max_size_kb.unwrap_or(500 * 1024) / 1024;

                            if ui
                                .add_enabled(
                                    limited,
                                    egui::DragValue::new(&mut megabytes)
                                        .range(1..=100_000)
                                        .suffix(" MB"),
                                )
                                .changed()
                            {
                                self.crawl_options.filters.max_size_kb = Some(megabytes * 1024);
                            }
                        });
                        ui.end_row();

                        ui.label("Не старше (дней):");
                        {
                            let mut pushed = self.crawl_options.filters.pushed_days.unwrap_or(0);

                            if ui
                                .add(egui::DragValue::new(&mut pushed).range(0..=3650))
                                .changed()
                            {
                                self.crawl_options.filters.pushed_days =
                                    (pushed > 0).then_some(pushed);
                            }
                        }
                        ui.end_row();

                        ui.label("Прочее:");
                        ui.horizontal_wrapped(|ui| {
                            ui.checkbox(&mut self.crawl_options.filters.include_forks, "форки");
                            ui.checkbox(&mut self.crawl_options.filters.include_archived, "архивные");
                            ui.checkbox(&mut self.crawl_options.skip_seen, "не повторять просканированные");
                            ui.checkbox(&mut self.crawl_options.verify, "проверять ключи онлайн");
                        });
                        ui.end_row();
                    });

                ui.add_space(2.0);
                ui.label(
                    egui::RichText::new(
                        "Фильтры применяются и к случайной выборке, и к поисковому запросу. Проверка ключей отправляет найденные токены в API провайдеров — включайте осознанно.",
                    )
                    .color(egui::Color32::from_gray(150)),
                );
            });
    }

    fn toolbar_repository(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        ui.horizontal(|ui| {
            if ui.button("Открыть репозиторий…").clicked() {
                if let Some(folder) = rfd::FileDialog::new().pick_folder() {
                    self.path_input = folder.display().to_string();
                }
            }

            ui.add(
                egui::TextEdit::singleline(&mut self.path_input)
                    .desired_width(320.0)
                    .hint_text("Путь к git-репозиторию"),
            );

            let scanning = self.pending.is_some();

            if ui
                .add_enabled(!scanning, egui::Button::new("Сканировать"))
                .clicked()
            {
                self.start_scan(ctx);
            }

            if ui
                .add_enabled(
                    self.result.is_some() && !scanning,
                    egui::Button::new("Экспорт JSON…"),
                )
                .clicked()
            {
                self.export_json();
            }

            if let Some(handle) = &self.pending {
                ui.add(
                    egui::ProgressBar::new(handle.fraction())
                        .desired_width(170.0)
                        .show_percentage(),
                );
                ui.label(format!(
                    "{}/{} коммитов, {:.1}s",
                    handle.scanned_commits(),
                    handle.total_commits(),
                    handle.started.elapsed().as_secs_f32()
                ));
            }
        });

        ui.add_space(4.0);

        ui.horizontal_wrapped(|ui| {
            ui.checkbox(&mut self.options.ai_only, "Только AI-ключи");
            ui.checkbox(&mut self.options.check_entropy, "Энтропийный поиск");
            ui.checkbox(&mut self.options.include_dangling, "Включая dangling");
            ui.checkbox(&mut self.options.staged, "Только staged (pre-commit)");

            ui.separator();
            ui.label("Порог энтропии:");
            ui.add(
                egui::Slider::new(&mut self.options.entropy_threshold, 2.0..=6.5).fixed_decimals(1),
            );

            ui.separator();
            ui.label("Мин. длина:");
            ui.add(egui::Slider::new(&mut self.options.min_entropy_len, 8..=64));
        });

        ui.add_space(2.0);

        egui::CollapsingHeader::new("Дополнительно: проверка, субмодули, notes, LFS, диапазон")
            .default_open(false)
            .show(ui, |ui| {
                ui.horizontal_wrapped(|ui| {
                    ui.checkbox(&mut self.options.verify, "Проверять ключи онлайн");
                    ui.checkbox(&mut self.options.include_submodules, "Субмодули");
                    ui.checkbox(&mut self.options.include_notes, "Git notes");
                    ui.checkbox(&mut self.options.include_lfs, "Git LFS");
                    ui.checkbox(&mut self.options.incremental, "Только новые коммиты");
                });

                ui.horizontal_wrapped(|ui| {
                    ui.label("Диапазон:");
                    ui.add(
                        egui::TextEdit::singleline(&mut self.range_input)
                            .desired_width(150.0)
                            .hint_text("HEAD~50..HEAD"),
                    );
                    ui.label("С даты:");
                    ui.add(
                        egui::TextEdit::singleline(&mut self.since_input)
                            .desired_width(110.0)
                            .hint_text("2026-01-01"),
                    );
                    ui.label("По дату:");
                    ui.add(
                        egui::TextEdit::singleline(&mut self.until_input)
                            .desired_width(110.0)
                            .hint_text("2026-12-31"),
                    );
                });

                ui.label(
                    egui::RichText::new(
                        "Проверка ключей отправляет найденные токены в API провайдеров. «Только новые коммиты» использует отметку прошлого скана этого репозитория; диапазон и даты задаются явно.",
                    )
                    .color(egui::Color32::from_gray(150)),
                );
            });
    }

    fn status_bar(&mut self, ui: &mut egui::Ui) {
        egui::Panel::bottom("status").show(ui, |ui| {
            ui.add_space(4.0);

            ui.horizontal_wrapped(|ui| {
                match self.mode {
                    GuiMode::Crawler => {
                        if let Some(totals) = &self.crawl_totals {
                            let leaks = self.crawl_repos.iter().filter(|r| !r.groups.is_empty()).count();
                            let unique: usize =
                                self.crawl_repos.iter().map(|r| r.groups.len()).sum();
                            let failing: usize =
                                self.crawl_repos.iter().map(|r| r.failing_findings).sum();
                            let resolved = self
                                .crawl_repos
                                .iter()
                                .flat_map(|repo| repo.groups.iter())
                                .filter(|group| self.resolved.is_resolved(&group.fingerprint))
                                .count();

                            ui.label(format!(
                                "Репозиториев: {} из {}",
                                totals.scanned, totals.discovered
                            ));
                            ui.separator();
                            ui.colored_label(
                                egui::Color32::from_rgb(120, 210, 220),
                                format!("С находками: {}", leaks),
                            );
                            ui.separator();
                            ui.label(format!(
                                "Уникальных находок: {} (всего {}), блокирующих: {}",
                                unique,
                                self.crawl_repos.iter().map(|r| r.findings.len()).sum::<usize>(),
                                failing
                            ));
                            ui.separator();
                            ui.label(format!("Устранено: {}", resolved));
                            ui.separator();
                            ui.label(format!(
                                "Ошибок: {}, пропущено: {} (уже видели: {})",
                                totals.failed, totals.skipped, self.crawl_skipped_known
                            ));
                        } else {
                            ui.label("Укажите параметры и нажмите «Запустить краулинг».");
                        }
                    }
                    GuiMode::Repository => {
                        let Some(result) = &self.result else {
                            ui.label("Укажите путь к репозиторию и нажмите «Сканировать».");
                            return;
                        };

                        let failing = result.failing_groups();
                        let resolved = result
                            .groups
                            .iter()
                            .filter(|group| self.resolved.is_resolved(&group.fingerprint))
                            .count();

                        ui.label(format!("Коммитов: {}", result.commits));
                        ui.separator();
                        ui.label(format!("Строк: {}", result.lines));

                        if result.skipped_lines > 0 || result.skipped_files > 0 {
                            ui.separator();
                            ui.colored_label(
                                egui::Color32::from_rgb(220, 190, 90),
                                format!(
                                    "Пропущено по лимитам: {} строк / {} файлов",
                                    result.skipped_lines, result.skipped_files
                                ),
                            );
                        }

                        ui.separator();
                        ui.label(format!(
                            "Уникальных находок: {} (всего {}), блокирующих: {}",
                            result.groups.len(),
                            result.findings.len(),
                            failing
                        ));
                        ui.separator();
                        ui.label(format!("Устранено: {}", resolved));
                        ui.separator();
                        ui.label(format!("Время: {:.2}s", result.duration.as_secs_f32()));
                    }
                }

                if let Some(status) = &self.export_status {
                    ui.separator();
                    ui.colored_label(egui::Color32::from_rgb(140, 220, 140), status.clone());
                }
            });

            ui.add_space(4.0);
        });
    }

    fn scan_list_panel(&mut self, ui: &mut egui::Ui) {
        egui::Panel::left("findings")
            .resizable(true)
            .default_size(470.0)
            .min_size(320.0)
            .max_size(760.0)
            .show(ui, |ui| {
                ui.add_space(6.0);

                ui.horizontal(|ui| {
                    ui.label("Поиск:");
                    ui.add(
                        egui::TextEdit::singleline(&mut self.query)
                            .desired_width(190.0)
                            .hint_text("правило, файл, коммит"),
                    );
                    ui.checkbox(&mut self.only_unresolved, "Только активные");
                });

                ui.add_space(4.0);

                ui.horizontal_wrapped(|ui| {
                    for severity in [
                        Severity::Critical,
                        Severity::High,
                        Severity::Medium,
                        Severity::Low,
                        Severity::Info,
                    ] {
                        let rank = severity.rank() as usize;
                        let count = self
                            .result
                            .as_ref()
                            .map(|result| {
                                result
                                    .groups
                                    .iter()
                                    .filter(|group| group.severity == severity)
                                    .count()
                            })
                            .unwrap_or(0);

                        let text = format!("{} {}", severity.label(), count);

                        if ui
                            .selectable_label(
                                self.severity_enabled[rank],
                                egui::RichText::new(text).color(severity_color(severity)),
                            )
                            .clicked()
                        {
                            self.severity_enabled[rank] = !self.severity_enabled[rank];
                        }
                    }
                });

                ui.separator();

                if self.result.is_none() {
                    ui.add_space(12.0);
                    ui.label(
                        egui::RichText::new(
                            "Результатов пока нет.\n\n1. Укажите путь к репозиторию.\n2. Нажмите «Сканировать».\n\nПапку можно перетащить прямо в окно.",
                        )
                        .color(egui::Color32::from_gray(150)),
                    );
                    return;
                }

                let visible = self.visible_scan_indices();

                if visible.is_empty() {
                    ui.add_space(12.0);
                    let has_groups = self
                        .result
                        .as_ref()
                        .map(|result| !result.groups.is_empty())
                        .unwrap_or(false);

                    if has_groups {
                        ui.label(
                            egui::RichText::new("Ничего не найдено по текущим фильтрам.")
                                .color(egui::Color32::from_gray(150)),
                        );
                    } else {
                        ui.label(
                            egui::RichText::new("Секретов и утечек не найдено.")
                                .color(egui::Color32::from_rgb(140, 220, 140)),
                        );
                    }

                    return;
                }

                let selected = self.selected;

                egui::ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        for index in visible {
                            let group = &self.result.as_ref().expect("checked above").groups[index];
                            let is_resolved = self.resolved.is_resolved(&group.fingerprint);
                            let response = ui.selectable_label(
                                selected == Some(index),
                                egui::RichText::new(truncate(&group_row_text(group), MAX_LIST_TEXT)).color(if is_resolved {
                                    egui::Color32::from_gray(130)
                                } else {
                                    severity_color(group.severity)
                                }),
                            );

                            if response.clicked() {
                                self.selected = Some(index);
                            }
                        }
                    });
            });
    }

    fn crawl_list_panel(&mut self, ui: &mut egui::Ui) {
        egui::Panel::left("crawl-repos")
            .resizable(true)
            .default_size(430.0)
            .min_size(300.0)
            .max_size(720.0)
            .show(ui, |ui| {
                ui.add_space(6.0);

                ui.horizontal(|ui| {
                    ui.label("Поиск по имени:");
                    ui.add(
                        egui::TextEdit::singleline(&mut self.crawl_filter)
                            .desired_width(180.0)
                            .hint_text("owner/repo"),
                    );
                });

                ui.add_space(4.0);

                ui.horizontal_wrapped(|ui| {
                    ui.colored_label(
                        egui::Color32::from_rgb(120, 210, 220),
                        format!("Найдено репозиториев: {}", self.crawl_repos.len()),
                    );
                    ui.separator();
                    ui.label(format!("Неудачных: {}", self.crawl_failed));
                });

                ui.separator();

                if self.crawl_repos.is_empty() {
                    ui.add_space(12.0);
                    let message = if self.crawl.is_some() {
                        "Сканирование идёт: первые результаты появятся выше по мере готовности."
                    } else {
                        "Отчёт пуст.\n\n1. Оставьте запрос пустым для случайных репозиториев.\n2. Задайте количество и глубину.\n3. Нажмите «Запустить краулинг»."
                    };

                    ui.label(egui::RichText::new(message).color(egui::Color32::from_gray(150)));
                    return;
                }

                let visible = self.visible_crawl_indices();

                if visible.is_empty() {
                    ui.add_space(12.0);
                    ui.label(
                        egui::RichText::new("Ничего не найдено по текущим фильтрам.")
                            .color(egui::Color32::from_gray(150)),
                    );
                    return;
                }

                let selected = self.selected_repo;
                let stored = self.resolved.clone();

                egui::ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        for index in visible {
                            let Some(repo) = self.crawl_repos.get(index) else {
                                continue;
                            };

                            let text = repo_row_text(repo, &stored);
                            let color = if repo.groups.is_empty() {
                                egui::Color32::from_gray(140)
                            } else {
                                severity_color(severity_from_rank(repo.max_severity_rank()))
                            };

                            if ui
                                .selectable_label(
                                    selected == Some(index),
                                    egui::RichText::new(text).color(color),
                                )
                                .clicked()
                            {
                                self.selected_repo = Some(index);
                                self.selected_crawl_group = Some(0);
                            }
                        }
                    });
            });
    }

    fn scan_detail_panel(&mut self, ui: &mut egui::Ui) {
        let Some(result) = &self.result else {
            ui.add_space(24.0);
            ui.label(
                egui::RichText::new("Панель подробностей")
                    .heading()
                    .color(egui::Color32::from_gray(160)),
            );
            return;
        };

        let Some(index) = self.selected.filter(|index| *index < result.groups.len()) else {
            ui.add_space(24.0);
            ui.label(
                egui::RichText::new("Выберите находку в списке слева.")
                    .color(egui::Color32::from_gray(160)),
            );
            return;
        };

        let group = &result.groups[index];

        render_group_details(ui, group, &mut self.resolved);
    }

    fn crawl_detail_panel(&mut self, ui: &mut egui::Ui) {
        let Some(repo_index) = self.selected_repo.filter(|index| *index < self.crawl_repos.len())
        else {
            ui.add_space(24.0);
            ui.label(
                egui::RichText::new(
                    "Выберите репозиторий слева: покажу найденные в нём ключи и историю вхождений.",
                )
                .color(egui::Color32::from_gray(160)),
            );
            return;
        };

        ui.add_space(8.0);
        ui.horizontal_wrapped(|ui| {
            ui.heading(self.crawl_repos[repo_index].repo_name.clone());
            ui.hyperlink_to(
                "открыть на GitHub",
                self.crawl_repos[repo_index].clone_url.clone(),
            );
            ui.label(
                egui::RichText::new(format!(
                    "уникальных находок: {}, блокирующих: {}, время скана: {} мс",
                    self.crawl_repos[repo_index].groups.len(),
                    self.crawl_repos[repo_index].failing_findings,
                    self.crawl_repos[repo_index].duration_ms
                ))
                .color(egui::Color32::from_gray(170)),
            );
        });

        ui.add_space(4.0);

        if self.crawl_repos[repo_index].groups.is_empty() {
            ui.label(
                egui::RichText::new("В этом репозитории ничего не найдено.")
                    .color(egui::Color32::from_rgb(140, 220, 140)),
            );
            return;
        }

        egui::Panel::left("crawl-groups")
            .resizable(true)
            .default_size(420.0)
            .min_size(280.0)
            .max_size(700.0)
            .show(ui, |ui| {
                egui::ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        let total_groups = self.crawl_repos[repo_index].groups.len();

                        for group_index in 0..total_groups {
                            let group = &self.crawl_repos[repo_index].groups[group_index];
                            let is_resolved = self.resolved.is_resolved(&group.fingerprint);

                            if ui
                                .selectable_label(
                                    self.selected_crawl_group == Some(group_index),
                                    egui::RichText::new(truncate(
                                        &group_row_text(group),
                                        MAX_LIST_TEXT,
                                    ))
                                    .color(
                                        if is_resolved {
                                            egui::Color32::from_gray(130)
                                        } else {
                                            severity_color(group.severity)
                                        },
                                    ),
                                )
                                .clicked()
                            {
                                self.selected_crawl_group = Some(group_index);
                            }
                        }
                    });
            });

        let group_index = self.selected_crawl_group.unwrap_or(0);
        let group = self.crawl_repos[repo_index]
            .groups
            .get(group_index)
            .cloned();

        if let Some(group) = group {
            render_group_details(ui, &group, &mut self.resolved);
        }
    }
}

impl eframe::App for GuiApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        self.poll_scan(&ctx);
        self.poll_crawl(&ctx);

        let dropped = ctx.input(|input| {
            input
                .raw
                .dropped_files
                .iter()
                .map(|file| file.path().to_path_buf())
                .find(|path| !path.as_os_str().is_empty())
        });

        if let Some(path) = dropped {
            self.path_input = path.display().to_string();
            self.mode = GuiMode::Repository;
        }

        self.toolbar(ui, &ctx);
        self.status_bar(ui);

        match self.mode {
            GuiMode::Crawler => {
                self.crawl_list_panel(ui);
                self.crawl_detail_panel(ui);
            }
            GuiMode::Repository => {
                self.scan_list_panel(ui);
                self.scan_detail_panel(ui);
            }
        }
    }
}

fn group_row_text(group: &FindingGroup) -> String {
    let location = group
        .occurrences
        .first()
        .map(|occurrence| occurrence.file_path.clone())
        .unwrap_or_default();

    let badge = match group.verification.as_ref().map(|verification| verification.status) {
        Some(VerificationStatus::Verified) => "✔ ",
        Some(VerificationStatus::Invalid) => "✖ ",
        _ => "",
    };

    let mut line = format!(
        "{}[{}] {}  ({})",
        badge,
        group.severity.label(),
        group.rule_name,
        location
    );

    if group.commit_count > 1 {
        line.push_str(&format!("  · {} коммитов", group.commit_count));
    }

    line
}

fn repo_row_text(repo: &CrawledRepo, resolved: &ResolvedState) -> String {
    if repo.groups.is_empty() {
        return format!("{}  · ничего не найдено", repo.repo_name);
    }

    let resolved_count = repo
        .groups
        .iter()
        .filter(|group| resolved.is_resolved(&group.fingerprint))
        .count();

    let verified = repo
        .groups
        .iter()
        .filter(|group| {
            group
                .verification
                .as_ref()
                .map(|verification| verification.status == VerificationStatus::Verified)
                .unwrap_or(false)
        })
        .count();

    let badge = if verified > 0 { "✔ " } else { "" };

    let mut text = format!(
        "{}{}  · {} находок ({} блокирующих)",
        badge,
        repo.repo_name,
        repo.groups.len(),
        repo.failing_findings
    );

    if verified > 0 {
        text.push_str(&format!(", подтверждено {}", verified));
    }

    if resolved_count > 0 {
        text.push_str(&format!(", устранено {}", resolved_count));
    }

    text
}

fn render_group_details(
    ui: &mut egui::Ui,
    group: &FindingGroup,
    resolved: &mut ResolvedState,
) {
    let is_resolved = resolved.is_resolved(&group.fingerprint);

    ui.add_space(8.0);
    ui.horizontal_wrapped(|ui| {
        ui.heading(group.rule_name.clone());
        ui.label(
            egui::RichText::new(group.severity.label())
                .color(severity_color(group.severity))
                .strong(),
        );
        ui.label(
            egui::RichText::new(group.category.label()).color(egui::Color32::from_rgb(120, 200, 255)),
        );
        ui.label(
            egui::RichText::new(format!("достоверность: {}", group.confidence))
                .color(egui::Color32::from_gray(170)),
        );
    });

    ui.add_space(6.0);

    let toggle_label = if is_resolved {
        "Снять отметку «устранено»"
    } else {
        "Отметить как устранённое"
    };

    if ui.button(toggle_label).clicked() {
        resolved.toggle(&group.fingerprint);
    }

    ui.separator();

    egui::Grid::new(format!("finding-details-{}", group.fingerprint))
        .num_columns(2)
        .spacing([18.0, 6.0])
        .show(ui, |ui| {
            ui.label("Секрет:");
            ui.colored_label(
                egui::Color32::from_rgb(255, 120, 120),
                group.secret_preview.clone(),
            );
            ui.end_row();

            ui.label("Отпечаток:");
            ui.monospace(group.fingerprint.clone());
            ui.end_row();

            ui.label("Семейство / энтропия:");
            ui.label(format!(
                "{} / {}",
                group.family,
                group
                    .entropy
                    .map(|entropy| format!("{:.2}", entropy))
                    .unwrap_or_else(|| "n/a".to_string())
            ));
            ui.end_row();

            ui.label("Встречается:");
            ui.label(format!(
                "{} коммит(ов), {} файл(ов)",
                group.commit_count, group.file_count
            ));
            ui.end_row();

            ui.label("Первый / последний:");
            ui.label(format!("{}  →  {}", group.first_seen, group.last_seen));
            ui.end_row();

            ui.label("Статус:");
            if is_resolved {
                ui.colored_label(
                    egui::Color32::from_rgb(140, 220, 140),
                    "устранено (состояние сохраняется между запусками)",
                );
            } else {
                ui.colored_label(egui::Color32::from_rgb(255, 150, 150), "активный риск");
            }
            ui.end_row();

            ui.label("Проверка ключа:");
            match group.verification.as_ref() {
                Some(verification) => {
                    ui.colored_label(
                        verification_color(verification.status),
                        format!("{} ({})", verification.label(), verification.detail),
                    );
                }
                None => {
                    ui.label("не выполнялась");
                }
            }
            ui.end_row();
        });

    ui.separator();
    ui.label(
        egui::RichText::new(format!("Вхождения ({})", group.occurrences.len()))
            .strong()
            .color(egui::Color32::from_gray(190)),
    );
    ui.add_space(4.0);

    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .show(ui, |ui| {
            for occurrence in group.occurrences.iter().take(MAX_OCCURRENCES_SHOWN) {
                ui.horizontal(|ui| {
                    ui.monospace(truncate(&occurrence.commit_id, 10));
                    ui.colored_label(
                        egui::Color32::from_gray(160),
                        truncate(&occurrence.commit_date, 24),
                    );
                    ui.label(truncate(&occurrence.file_path, 60));
                    ui.colored_label(
                        egui::Color32::from_rgb(220, 200, 120),
                        format!(":{}", occurrence.line_number),
                    );
                    ui.colored_label(
                        egui::Color32::from_gray(140),
                        truncate(&occurrence.commit_author, 24),
                    );
                });
            }

            if group.occurrences.len() > MAX_OCCURRENCES_SHOWN {
                ui.label(format!(
                    "… ещё {} вхождений",
                    group.occurrences.len() - MAX_OCCURRENCES_SHOWN
                ));
            }
        });
}

fn severity_from_rank(rank: u8) -> Severity {
    match rank {
        4 => Severity::Critical,
        3 => Severity::High,
        2 => Severity::Medium,
        1 => Severity::Low,
        _ => Severity::Info,
    }
}

fn severity_color(severity: Severity) -> egui::Color32 {
    match severity {
        Severity::Critical => egui::Color32::from_rgb(255, 95, 95),
        Severity::High => egui::Color32::from_rgb(255, 175, 80),
        Severity::Medium => egui::Color32::from_rgb(120, 170, 255),
        Severity::Low => egui::Color32::from_gray(160),
        Severity::Info => egui::Color32::from_rgb(120, 210, 220),
    }
}

fn verification_color(status: VerificationStatus) -> egui::Color32 {
    match status {
        VerificationStatus::Verified => egui::Color32::from_rgb(120, 220, 140),
        VerificationStatus::Invalid => egui::Color32::from_gray(150),
        VerificationStatus::Unknown => egui::Color32::from_rgb(230, 190, 90),
        VerificationStatus::Error => egui::Color32::from_rgb(230, 120, 120),
    }
}

fn truncate(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        return text.to_string();
    }

    let mut output: String = text.chars().take(max.saturating_sub(1)).collect();
    output.push('…');
    output
}

pub fn launch(initial_path: Option<PathBuf>, options: Option<ScanOptions>) -> eframe::Result<()> {
    let native_options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1280.0, 820.0])
            .with_min_inner_size([980.0, 620.0])
            .with_title("Git Secret Hunter — GUI"),
        ..Default::default()
    };

    eframe::run_native(
        "Git Secret Hunter",
        native_options,
        Box::new(move |creation| {
            let app = GuiApp::new(
                initial_path.clone(),
                options.clone().unwrap_or_default(),
                creation,
            );

            Ok(Box::new(app))
        }),
    )
}
