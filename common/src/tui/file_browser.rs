//! File browser popup widget and state

use ratatui::{
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, List, ListItem, ListState},
    Frame,
};

use super::theme;

/// State for the file browser popup. Manages the current directory,
/// entries, selection, and scroll position.
pub struct FileBrowserState {
    pub dir: std::path::PathBuf,
    pub entries: Vec<std::path::PathBuf>,
    pub selected: usize,
    pub scroll: usize,
}

impl FileBrowserState {
    /// Create a new browser rooted at the current working directory.
    pub fn new() -> Self {
        let dir = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));
        let mut s = Self { dir, entries: Vec::new(), selected: 0, scroll: 0 };
        s.refresh();
        s
    }

    /// Reload directory entries (dirs first, then files, both sorted).
    pub fn refresh(&mut self) {
        self.entries.clear();
        if let Ok(rd) = std::fs::read_dir(&self.dir) {
            let mut dirs: Vec<std::path::PathBuf> = Vec::new();
            let mut files: Vec<std::path::PathBuf> = Vec::new();
            for entry in rd.flatten() {
                let path = entry.path();
                if path.is_dir() { dirs.push(path); } else { files.push(path); }
            }
            dirs.sort();
            files.sort();
            self.entries.extend(dirs);
            self.entries.extend(files);
        }
        self.selected = self.selected.min(self.entries.len().saturating_sub(1));
    }

    pub fn selected_path(&self) -> Option<&std::path::PathBuf> {
        self.entries.get(self.selected)
    }

    /// Move the selection by `delta` rows, keeping it in bounds and scrolling into view.
    pub fn move_selection(&mut self, delta: i32) {
        let count = self.entries.len();
        if count == 0 { return; }
        if delta < 0 {
            self.selected = self.selected.saturating_sub((-delta) as usize);
        } else {
            self.selected = (self.selected + delta as usize).min(count - 1);
        }
        self.clamp_scroll();
    }

    /// Navigate into the selected directory (no-op if selected entry is a file).
    /// Returns `true` if navigation happened.
    pub fn enter_dir(&mut self) -> bool {
        if let Some(path) = self.selected_path().cloned() {
            if path.is_dir() {
                self.dir = path;
                self.selected = 0;
                self.scroll = 0;
                self.refresh();
                return true;
            }
        }
        false
    }

    /// Navigate to the parent directory.
    pub fn go_up(&mut self) {
        if let Some(parent) = self.dir.parent().map(|p| p.to_path_buf()) {
            self.dir = parent;
            self.selected = 0;
            self.scroll = 0;
            self.refresh();
        }
    }

    fn clamp_scroll(&mut self) {
        let visible = 20usize;
        if self.selected < self.scroll {
            self.scroll = self.selected;
        } else if self.selected >= self.scroll + visible {
            self.scroll = self.selected + 1 - visible;
        }
    }
}

impl Default for FileBrowserState {
    fn default() -> Self { Self::new() }
}

/// A file browser overlay widget. Renders as a centered popup.
pub struct FileBrowserWidget<'a> {
    pub state: &'a FileBrowserState,
}

impl<'a> FileBrowserWidget<'a> {
    pub fn render(self, frame: &mut Frame) {
        let area = frame.area();
        let width = 60u16.min(area.width.saturating_sub(4));
        let height = 24u16.min(area.height.saturating_sub(4));
        let x = area.x + area.width.saturating_sub(width) / 2;
        let y = area.y + area.height.saturating_sub(height) / 2;
        let popup_area = ratatui::layout::Rect { x, y, width, height };

        frame.render_widget(Clear, popup_area);

        let title = format!(" {} ", self.state.dir.display());
        let block = Block::default()
            .title(title.as_str())
            .title_bottom(" j/k:move  l/Enter:open  h/←:up  Esc:cancel ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(theme::CYAN))
            .style(Style::default().bg(theme::BG));

        let items: Vec<ListItem> = self.state.entries.iter().map(|p| {
            let is_dir = p.is_dir();
            let name = p.file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_else(|| p.to_string_lossy().to_string());
            let display = if is_dir { format!("{name}/") } else { name };
            let color = if is_dir { theme::CYAN } else { theme::FG };
            ListItem::new(Line::from(Span::styled(display, Style::default().fg(color))))
        }).collect();

        let list = List::new(items)
            .block(block)
            .highlight_style(
                Style::default().fg(theme::BG).bg(theme::CYAN).add_modifier(Modifier::BOLD),
            )
            .highlight_symbol("> ");

        let mut list_state = ListState::default();
        list_state.select(Some(self.state.selected));

        frame.render_stateful_widget(list, popup_area, &mut list_state);
    }
}
