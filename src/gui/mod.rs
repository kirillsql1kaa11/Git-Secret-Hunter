pub mod scan;

use crate::scanner::Severity;
use crate::tui::state::ResolvedState;
use eframe::egui;
use scan::{ScanHandle, ScanOptions, ScanOutcome, ScanResult, spawn_scan};
use std::path::PathBuf;

const MAX_LIST_TEXT: usize = 72;
const MAX_OCCURRENCES_SHOWN: usize = 200;

pub struct GuiApp {
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

        Self {
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
        }
    }

    fn poll_scan(&mut self, ctx: &egui::Context) {
        let Some(handle) = &self.pending else {
            return;
        };

        match handle.poll() {
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
        let Some(result) = &self.result else {
            return;
        };

        let default_name = format!("secret-hunter-report-{}s.json", result.duration.as_secs());

        let Some(target) = rfd::FileDialog::new()
            .set_file_name(default_name)
            .add_filter("JSON", &["json"])
            .save_file()
        else {
            return;
        };

        match std::fs::write(&target, result.to_json()) {
            Ok(()) => self.export_status = Some(format!("Отчёт сохранён: {}", target.display())),
            Err(error) => self.export_status = Some(format!("Ошибка записи: {}", error)),
        }
    }

    fn visible_indices(&self) -> Vec<usize> {
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

    fn toolbar(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        egui::Panel::top("toolbar").show(ui, |ui| {
            ui.add_space(6.0);

            ui.horizontal(|ui| {
                ui.heading("Git Secret Hunter");
                ui.label(
                    egui::RichText::new("GUI")
                        .color(egui::Color32::from_rgb(120, 200, 255))
                        .strong(),
                );
                ui.separator();

                if ui.button("Открыть репозиторий…").clicked() {
                    if let Some(folder) = rfd::FileDialog::new().pick_folder() {
                        self.path_input = folder.display().to_string();
                    }
                }

                ui.add(
                    egui::TextEdit::singleline(&mut self.path_input)
                        .desired_width(360.0)
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
                    egui::Slider::new(&mut self.options.entropy_threshold, 2.0..=6.5)
                        .fixed_decimals(1),
                );

                ui.separator();
                ui.label("Мин. длина:");
                ui.add(egui::Slider::new(&mut self.options.min_entropy_len, 8..=64));
            });

            if let Some(error) = &self.error {
                ui.add_space(2.0);
                ui.colored_label(egui::Color32::from_rgb(255, 100, 100), error.clone());
            }

            ui.add_space(6.0);
        });
    }

    fn status_bar(&mut self, ui: &mut egui::Ui) {
        egui::Panel::bottom("status").show(ui, |ui| {
            ui.add_space(4.0);

            ui.horizontal_wrapped(|ui| {
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

                if let Some(status) = &self.export_status {
                    ui.separator();
                    ui.colored_label(egui::Color32::from_rgb(140, 220, 140), status.clone());
                }
            });

            ui.add_space(4.0);
        });
    }

    fn list_panel(&mut self, ui: &mut egui::Ui) {
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

                let visible = self.visible_indices();

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
                            let location = group
                                .occurrences
                                .first()
                                .map(|occurrence| occurrence.file_path.clone())
                                .unwrap_or_default();

                            let mut line = format!(
                                "[{}] {}  ({})",
                                group.severity.label(),
                                group.rule_name,
                                location
                            );

                            if group.commit_count > 1 {
                                line.push_str(&format!("  · {} коммитов", group.commit_count));
                            }

                            if is_resolved {
                                line.push_str("  · устранено");
                            }

                            let response = ui.selectable_label(
                                selected == Some(index),
                                egui::RichText::new(truncate(&line, MAX_LIST_TEXT)).color(
                                    if is_resolved {
                                        egui::Color32::from_gray(130)
                                    } else {
                                        severity_color(group.severity)
                                    },
                                ),
                            );

                            if response.clicked() {
                                self.selected = Some(index);
                            }
                        }
                    });
            });
    }

    fn detail_panel(&mut self, ui: &mut egui::Ui) {
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
        let is_resolved = self.resolved.is_resolved(&group.fingerprint);

        ui.add_space(8.0);
        ui.horizontal_wrapped(|ui| {
            ui.heading(group.rule_name.clone());
            ui.label(
                egui::RichText::new(group.severity.label())
                    .color(severity_color(group.severity))
                    .strong(),
            );
            ui.label(
                egui::RichText::new(group.category.label())
                    .color(egui::Color32::from_rgb(120, 200, 255)),
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
            self.resolved.toggle(&group.fingerprint);
        }

        ui.separator();

        egui::Grid::new("finding-details")
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
}

impl eframe::App for GuiApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        self.poll_scan(&ctx);

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
        }

        self.toolbar(ui, &ctx);
        self.status_bar(ui);
        self.list_panel(ui);
        self.detail_panel(ui);
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
