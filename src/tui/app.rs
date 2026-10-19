use crate::scanner::rules::Severity;
use crate::scanner::FindingGroup;
use crate::tui::state::ResolvedState;
use ratatui::widgets::ListState;

#[derive(Debug, Clone)]
pub struct TuiItem {
    pub group: FindingGroup,
    pub is_resolved: bool,
}

pub struct App {
    pub items: Vec<TuiItem>,
    pub selected_index: usize,
    pub should_quit: bool,
    pub list_state: ListState,
    pub resolved: ResolvedState,
}

impl App {
    pub fn new(groups: Vec<FindingGroup>) -> Self {
        Self::with_resolved(groups, ResolvedState::load())
    }

    pub fn with_resolved(groups: Vec<FindingGroup>, resolved: ResolvedState) -> Self {
        let items: Vec<TuiItem> = groups
            .into_iter()
            .map(|group| TuiItem {
                is_resolved: resolved.is_resolved(&group.fingerprint),
                group,
            })
            .collect();

        let mut list_state = ListState::default();
        if !items.is_empty() {
            list_state.select(Some(0));
        }

        Self {
            items,
            selected_index: 0,
            should_quit: false,
            list_state,
            resolved,
        }
    }

    pub fn select(&mut self, index: usize) {
        if self.items.is_empty() {
            return;
        }

        self.selected_index = index.min(self.items.len() - 1);
        self.list_state.select(Some(self.selected_index));
    }

    pub fn next(&mut self) {
        self.select(self.selected_index.saturating_add(1));
    }

    pub fn previous(&mut self) {
        self.select(self.selected_index.saturating_sub(1));
    }

    pub fn page_down(&mut self) {
        self.select(self.selected_index.saturating_add(10));
    }

    pub fn page_up(&mut self) {
        self.select(self.selected_index.saturating_sub(10));
    }

    pub fn first(&mut self) {
        self.select(0);
    }

    pub fn last(&mut self) {
        if !self.items.is_empty() {
            self.select(self.items.len() - 1);
        }
    }

    pub fn toggle_resolved(&mut self) {
        if let Some(item) = self.items.get_mut(self.selected_index) {
            let fingerprint = item.group.fingerprint.clone();
            item.is_resolved = self.resolved.toggle(&fingerprint);
        }
    }

    pub fn resolved_count(&self) -> usize {
        self.items.iter().filter(|item| item.is_resolved).count()
    }

    pub fn current_item(&self) -> Option<&TuiItem> {
        self.items.get(self.selected_index)
    }

    pub fn counts_by_severity(&self) -> (usize, usize, usize, usize, usize) {
        let mut critical = 0;
        let mut high = 0;
        let mut medium = 0;
        let mut low = 0;
        let mut info = 0;

        for item in &self.items {
            match item.group.severity {
                Severity::Critical => critical += 1,
                Severity::High => high += 1,
                Severity::Medium => medium += 1,
                Severity::Low => low += 1,
                Severity::Info => info += 1,
            }
        }

        (critical, high, medium, low, info)
    }
}
