use crate::scanner::rules::Severity;
use crate::scanner::Finding;

#[derive(Debug, Clone)]
pub struct TuiItem {
    pub finding: Finding,
    pub is_resolved: bool,
}

pub struct App {
    pub items: Vec<TuiItem>,
    pub selected_index: usize,
    pub should_quit: bool,
}

impl App {
    pub fn new(findings: Vec<Finding>) -> Self {
        let items = findings
            .into_iter()
            .map(|f| TuiItem {
                finding: f,
                is_resolved: false,
            })
            .collect();

        Self {
            items,
            selected_index: 0,
            should_quit: false,
        }
    }

    pub fn next(&mut self) {
        if !self.items.is_empty() && self.selected_index + 1 < self.items.len() {
            self.selected_index += 1;
        }
    }

    pub fn previous(&mut self) {
        if self.selected_index > 0 {
            self.selected_index -= 1;
        }
    }

    pub fn toggle_resolved(&mut self) {
        if let Some(item) = self.items.get_mut(self.selected_index) {
            item.is_resolved = !item.is_resolved;
        }
    }

    pub fn current_item(&self) -> Option<&TuiItem> {
        self.items.get(self.selected_index)
    }

    pub fn counts_by_severity(&self) -> (usize, usize, usize, usize) {
        let mut crit = 0;
        let mut high = 0;
        let mut med = 0;
        let mut low = 0;

        for item in &self.items {
            match item.finding.severity {
                Severity::Critical => crit += 1,
                Severity::High => high += 1,
                Severity::Medium => med += 1,
                Severity::Low => low += 1,
            }
        }

        (crit, high, med, low)
    }
}
