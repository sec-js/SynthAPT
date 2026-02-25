use ratatui::layout::Rect;
use super::panes::WrapMapping;

/// Text selection state for panes that support mouse-driven text selection
#[derive(Clone, Debug, Default)]
pub struct TextSelection {
    /// Start position (line, column) - where mouse was pressed
    pub start: Option<(usize, usize)>,
    /// End position (line, column) - where mouse is now
    pub end: Option<(usize, usize)>,
    /// Whether actively dragging to select
    pub selecting: bool,
    /// Last click time for double-click detection
    pub last_click_time: Option<std::time::Instant>,
    /// Last click position for double-click detection
    pub last_click_pos: Option<(usize, usize)>,
}

impl TextSelection {
    /// Get normalized selection range (start always before end)
    pub fn range(&self) -> Option<((usize, usize), (usize, usize))> {
        match (self.start, self.end) {
            (Some(start), Some(end)) => {
                if start.0 < end.0 || (start.0 == end.0 && start.1 <= end.1) {
                    Some((start, end))
                } else {
                    Some((end, start))
                }
            }
            _ => None,
        }
    }

    /// Check if a position is within the selection
    pub fn contains(&self, line: usize, col: usize) -> bool {
        if let Some(((start_line, start_col), (end_line, end_col))) = self.range() {
            if line < start_line || line > end_line {
                return false;
            }
            if line == start_line && line == end_line {
                return col >= start_col && col < end_col;
            }
            if line == start_line {
                return col >= start_col;
            }
            if line == end_line {
                return col < end_col;
            }
            true
        } else {
            false
        }
    }

    /// Clear the selection
    pub fn clear(&mut self) {
        self.start = None;
        self.end = None;
        self.selecting = false;
    }

    /// Check if there's an active selection
    pub fn is_active(&self) -> bool {
        self.start.is_some() && self.end.is_some()
    }
}

/// Unified output area info for panes that support text selection
#[derive(Clone, Debug, Default)]
pub struct PaneOutputInfo {
    /// The output area rectangle
    pub area: Rect,
    /// First visible line index (for scroll offset)
    pub first_visible: usize,
    /// Wrap mapping for converting visual to logical positions
    pub wrap_mapping: WrapMapping,
    /// Horizontal scroll offset
    pub h_scroll: usize,
}

/// Trait for panes that support scrolling
pub trait Scrollable {
    fn scroll_offset(&self) -> usize;
    fn set_scroll_offset(&mut self, offset: usize);
    fn line_count(&self) -> usize;

    // Horizontal scrolling (default: no-op for panes that don't support it)
    fn horizontal_scroll(&self) -> usize { 0 }
    fn set_horizontal_scroll(&mut self, _offset: usize) {}
    fn max_line_width(&self) -> usize { 0 }

    /// Scroll up (view older content)
    fn scroll_up(&mut self, amount: usize) {
        self.set_scroll_offset(self.scroll_offset().saturating_add(amount));
    }

    /// Scroll down (view newer content)
    fn scroll_down(&mut self, amount: usize) {
        self.set_scroll_offset(self.scroll_offset().saturating_sub(amount));
    }

    /// Scroll left
    fn scroll_left(&mut self, amount: usize) {
        self.set_horizontal_scroll(self.horizontal_scroll().saturating_sub(amount));
    }

    /// Scroll right
    fn scroll_right(&mut self, amount: usize) {
        self.set_horizontal_scroll(self.horizontal_scroll().saturating_add(amount));
    }

    /// Jump to oldest content
    fn scroll_to_top(&mut self) {
        self.set_scroll_offset(self.line_count());
    }

    /// Jump to newest content (bottom)
    fn scroll_to_bottom(&mut self) {
        self.set_scroll_offset(0);
    }

    /// Jump to leftmost content
    fn scroll_to_left(&mut self) {
        self.set_horizontal_scroll(0);
    }

    /// Clamp scroll offset to valid range given visible height
    fn clamp_scroll(&mut self, visible_height: usize) {
        let max = self.line_count().saturating_sub(visible_height);
        if self.scroll_offset() > max {
            self.set_scroll_offset(max);
        }
    }

    /// Clamp horizontal scroll to valid range given visible width
    fn clamp_horizontal_scroll(&mut self, visible_width: usize) {
        let max = self.max_line_width().saturating_sub(visible_width);
        if self.horizontal_scroll() > max {
            self.set_horizontal_scroll(max);
        }
    }

    /// Calculate visible line range: (start_idx, end_idx)
    fn visible_range(&self, visible_height: usize) -> (usize, usize) {
        let total = self.line_count();
        let start = total.saturating_sub(visible_height + self.scroll_offset());
        let end = total.saturating_sub(self.scroll_offset());
        (start, end)
    }
}

/// Trait for panes that support text selection
pub trait Selectable: Scrollable {
    fn selection(&self) -> &TextSelection;
    fn selection_mut(&mut self) -> &mut TextSelection;
    fn get_line_text(&self, index: usize) -> Option<String>;

    /// Start a new selection at position
    fn start_selection(&mut self, line: usize, col: usize) {
        let sel = self.selection_mut();
        sel.start = Some((line, col));
        sel.end = Some((line, col));
        sel.selecting = true;
        sel.last_click_time = Some(std::time::Instant::now());
        sel.last_click_pos = Some((line, col));
    }

    /// Extend selection to position
    fn extend_selection(&mut self, line: usize, col: usize) {
        let sel = self.selection_mut();
        if sel.selecting {
            sel.end = Some((line, col));
        }
    }

    /// Finish selection
    fn finish_selection(&mut self) {
        self.selection_mut().selecting = false;
    }

    /// Clear selection
    fn clear_selection(&mut self) {
        self.selection_mut().clear();
    }

    /// Check if position was double-clicked
    fn is_double_click(&self, line: usize, col: usize) -> bool {
        let sel = self.selection();
        let now = std::time::Instant::now();
        sel.last_click_time.map_or(false, |t| {
            now.duration_since(t).as_millis() < 500
        }) && sel.last_click_pos == Some((line, col))
    }

    /// Select word at position
    fn select_word_at(&mut self, line: usize, col: usize) {
        if let Some(text) = self.get_line_text(line) {
            let (start, end) = find_word_boundaries(&text, col);
            let sel = self.selection_mut();
            sel.start = Some((line, start));
            sel.end = Some((line, end));
            sel.selecting = false;
            sel.last_click_time = None;
            sel.last_click_pos = None;
        }
    }

    /// Get selected text
    fn get_selected_text(&self) -> Option<String> {
        let ((start_line, start_col), (end_line, end_col)) = self.selection().range()?;
        let mut result = String::new();

        for idx in start_line..=end_line {
            let Some(text) = self.get_line_text(idx) else { continue };

            if idx == start_line && idx == end_line {
                let start = start_col.min(text.len());
                let end = end_col.min(text.len());
                result.push_str(&text[start..end]);
            } else if idx == start_line {
                let start = start_col.min(text.len());
                result.push_str(&text[start..]);
                result.push('\n');
            } else if idx == end_line {
                let end = end_col.min(text.len());
                result.push_str(&text[..end]);
            } else {
                result.push_str(&text);
                result.push('\n');
            }
        }

        if result.is_empty() { None } else { Some(result) }
    }
}

/// Find word boundaries around a column position in text.
/// Returns (start, end) column indices for the word.
pub fn find_word_boundaries(text: &str, col: usize) -> (usize, usize) {
    let chars: Vec<char> = text.chars().collect();
    let col = col.min(chars.len().saturating_sub(1));

    if chars.is_empty() {
        return (0, 0);
    }

    let is_word_char = |c: char| c.is_alphanumeric() || c == '_' || c == '-';

    // If we're on a non-word character, select just that character
    if !is_word_char(chars[col]) {
        return (col, col + 1);
    }

    // Find start of word (scan backwards)
    let mut start = col;
    while start > 0 && is_word_char(chars[start - 1]) {
        start -= 1;
    }

    // Find end of word (scan forwards)
    let mut end = col;
    while end < chars.len() && is_word_char(chars[end]) {
        end += 1;
    }

    (start, end)
}
