//! Reusable scrollable pane component with optional selection highlighting

use ratatui::{
    layout::Rect,
    style::{Color, Style},
    text::{Line, Span},
    widgets::{Paragraph, Scrollbar, ScrollbarOrientation, ScrollbarState, Wrap},
    Frame,
};
use unicode_width::UnicodeWidthStr;

use crate::tui::text::TextSelection;

/// Mapping from visual rows to logical lines for wrapped text
/// Each entry is (logical_line_idx, char_offset_in_line)
#[derive(Debug, Clone, Default)]
pub struct WrapMapping {
    /// For each visual row: (logical_line_index, char_offset_within_line)
    pub visual_to_logical: Vec<(usize, usize)>,
}

/// Result from ScrollablePane::render() with all info callers need
#[derive(Debug, Clone)]
pub struct ScrollResult {
    /// First visible logical line index
    pub first_visible: usize,
    /// Total logical lines
    pub total_lines: usize,
    /// Wrap mapping for selection handling
    pub wrap_mapping: WrapMapping,
    /// Maximum valid scroll offset (for clamping stored state)
    pub max_scroll: usize,
    /// The actual scroll offset used after clamping (callers should update their state to this)
    pub clamped_offset: usize,
}

impl WrapMapping {
    /// Convert a visual position (row, col) to logical position (line, col)
    pub fn visual_to_logical_pos(&self, visual_row: usize, visual_col: usize) -> (usize, usize) {
        if let Some(&(line_idx, char_offset)) = self.visual_to_logical.get(visual_row) {
            (line_idx, char_offset + visual_col)
        } else {
            // Fallback: assume 1:1 mapping
            (visual_row, visual_col)
        }
    }
}

/// Renders a scrollable output area with optional scrollbar
pub struct ScrollablePane<'a> {
    lines: &'a [Line<'a>],
    scroll_offset: usize,
    horizontal_scroll: usize,
    scroll_from_top: bool,
    show_scrollbar: bool,
    wrap: bool,
}

impl<'a> ScrollablePane<'a> {
    pub fn new(lines: &'a [Line<'a>]) -> Self {
        Self {
            lines,
            scroll_offset: 0,
            horizontal_scroll: 0,
            scroll_from_top: false,
            show_scrollbar: true,
            wrap: false,
        }
    }

    pub fn scroll_offset(mut self, offset: usize) -> Self {
        self.scroll_offset = offset;
        self
    }

    pub fn horizontal_scroll(mut self, offset: usize) -> Self {
        self.horizontal_scroll = offset;
        self
    }

    pub fn scroll_from_top(mut self, from_top: bool) -> Self {
        self.scroll_from_top = from_top;
        self
    }

    pub fn show_scrollbar(mut self, show: bool) -> Self {
        self.show_scrollbar = show;
        self
    }

    pub fn wrap(mut self, wrap: bool) -> Self {
        self.wrap = wrap;
        self
    }

    /// Render the scrollable output and return ScrollResult with all info needed by callers
    pub fn render(self, frame: &mut Frame, area: Rect) -> ScrollResult {
        let total_logical_lines = self.lines.len();
        let visible_height = area.height as usize;

        // Check if we need a scrollbar (estimate - will refine with wrap)
        let has_scrollbar = self.show_scrollbar && total_logical_lines > visible_height;
        let content_width = if has_scrollbar {
            area.width.saturating_sub(1)
        } else {
            area.width
        };

        let h_scroll = self.horizontal_scroll;
        let wrap_enabled = self.wrap;

        if wrap_enabled {
            // WRAPPED MODE: scroll in visual rows, not logical lines.
            // Optimization: compute visual row counts per line, then only
            // wrap-map and render the lines near the viewport.
            let width = content_width as usize;

            // Step 1: compute visual row count per logical line (cheap: just counting)
            let row_counts: Vec<usize> = self.lines.iter()
                .map(|line| count_visual_rows(line, width))
                .collect();
            let total_visual_rows: usize = row_counts.iter().sum();

            // Step 2: find the visible window of logical lines
            let rows_needed = visible_height + self.scroll_offset;

            let (first_logical, skip_rows_in_first, clamped_offset) = if self.scroll_from_top {
                // Scroll from top: walk forward
                let target_row = self.scroll_offset.min(total_visual_rows.saturating_sub(visible_height));
                let mut accumulated = 0;
                let mut first = 0;
                let mut skip = 0;
                for (i, &count) in row_counts.iter().enumerate() {
                    if accumulated + count > target_row {
                        first = i;
                        skip = target_row - accumulated;
                        break;
                    }
                    accumulated += count;
                }
                let max_scroll = total_visual_rows.saturating_sub(visible_height);
                (first, skip, self.scroll_offset.min(max_scroll))
            } else {
                // Scroll from bottom: walk backward from end
                let mut accumulated = 0usize;
                let mut first = self.lines.len();
                let mut skip = 0;
                for i in (0..self.lines.len()).rev() {
                    accumulated += row_counts[i];
                    if accumulated >= rows_needed {
                        first = i;
                        skip = accumulated - rows_needed;
                        break;
                    }
                }
                if accumulated < rows_needed {
                    first = 0;
                    skip = 0;
                }
                let max_scroll = total_visual_rows.saturating_sub(visible_height);
                (first, skip, self.scroll_offset.min(max_scroll))
            };

            // Step 3: slice to only the lines that could be visible (with margin)
            // We need enough lines to cover visible_height visual rows after skipping skip_rows_in_first
            let mut rows_covered = 0usize;
            let mut last_logical = first_logical;
            for i in first_logical..self.lines.len() {
                rows_covered += row_counts[i];
                last_logical = i + 1;
                if rows_covered >= rows_needed + visible_height {
                    break;
                }
            }

            let slice: Vec<Line> = self.lines[first_logical..last_logical]
                .iter()
                .cloned()
                .collect();

            // Step 4: compute wrap mapping only for the visible slice
            let slice_wrap = compute_wrap_mapping(&slice, width, first_logical);
            let visible_wrap: Vec<(usize, usize)> = slice_wrap.visual_to_logical
                .iter()
                .skip(skip_rows_in_first)
                .take(visible_height)
                .copied()
                .collect();
            let wrap_mapping = WrapMapping { visual_to_logical: visible_wrap };

            // Step 5: render only the sliced lines
            let content_area = Rect {
                x: area.x,
                y: area.y,
                width: content_width,
                height: area.height,
            };

            let paragraph = Paragraph::new(slice)
                .wrap(Wrap { trim: false })
                .scroll((skip_rows_in_first as u16, 0));
            frame.render_widget(paragraph, content_area);

            let max_scroll = total_visual_rows.saturating_sub(visible_height);

            // Render scrollbar
            if total_visual_rows > visible_height {
                let scrollbar_position = if self.scroll_from_top {
                    self.scroll_offset.min(max_scroll)
                } else {
                    max_scroll.saturating_sub(clamped_offset)
                };
                render_scrollbar(frame, area, max_scroll, scrollbar_position);
            }

            ScrollResult {
                first_visible: first_logical,
                total_lines: total_logical_lines,
                wrap_mapping,
                max_scroll,
                clamped_offset,
            }
        } else {
            // NON-WRAPPED MODE: scroll in logical lines
            let first_visible = if self.scroll_from_top {
                self.scroll_offset.min(total_logical_lines.saturating_sub(visible_height))
            } else {
                if total_logical_lines > visible_height {
                    total_logical_lines.saturating_sub(visible_height + self.scroll_offset)
                } else {
                    0
                }
            };

            let visible_lines: Vec<Line> = self.lines
                .iter()
                .skip(first_visible)
                .take(visible_height)
                .map(|line| {
                    if h_scroll > 0 {
                        apply_horizontal_scroll(line.clone(), h_scroll)
                    } else {
                        line.clone()
                    }
                })
                .collect();

            // Simple 1:1 mapping when not wrapping
            let visual_to_logical: Vec<(usize, usize)> = (0..visible_lines.len())
                .map(|i| (first_visible + i, 0))
                .collect();
            let wrap_mapping = WrapMapping { visual_to_logical };

            // Render content
            let content_area = Rect {
                x: area.x,
                y: area.y,
                width: content_width,
                height: area.height,
            };

            let paragraph = Paragraph::new(visible_lines);
            frame.render_widget(paragraph, content_area);

            // Calculate max scroll and clamped offset for callers
            let max_scroll = total_logical_lines.saturating_sub(visible_height);
            let clamped_offset = self.scroll_offset.min(max_scroll);

            // Render scrollbar if needed
            if has_scrollbar {
                let scrollbar_position = if self.scroll_from_top {
                    clamped_offset
                } else {
                    max_scroll.saturating_sub(clamped_offset)
                };

                render_scrollbar(frame, area, max_scroll, scrollbar_position);
            }

            ScrollResult {
                first_visible,
                total_lines: total_logical_lines,
                wrap_mapping,
                max_scroll,
                clamped_offset,
            }
        }
    }
}

/// Render the scrollbar
fn render_scrollbar(frame: &mut Frame, area: Rect, max_scroll: usize, position: usize) {
    let scrollbar = Scrollbar::new(ScrollbarOrientation::VerticalRight)
        .begin_symbol(Some("↑"))
        .end_symbol(Some("↓"))
        .track_symbol(Some("│"))
        .thumb_symbol("█");

    let mut scrollbar_state = ScrollbarState::new(max_scroll).position(position);

    let scrollbar_area = Rect {
        x: area.x + area.width - 1,
        y: area.y,
        width: 1,
        height: area.height,
    };

    frame.render_stateful_widget(scrollbar, scrollbar_area, &mut scrollbar_state);
}

/// Count how many visual rows a single line occupies when wrapped to the given width.
/// Zero-allocation: iterates spans directly without building a String.
fn count_visual_rows(line: &Line, width: usize) -> usize {
    if width == 0 {
        return 1;
    }
    let mut rows = 0usize;
    let mut row_width = 0usize;
    let mut has_content = false;
    for span in &line.spans {
        for ch in span.content.chars() {
            has_content = true;
            let ch_width = unicode_width::UnicodeWidthChar::width(ch).unwrap_or(1);
            if row_width + ch_width > width {
                rows += 1;
                row_width = ch_width;
            } else {
                row_width += ch_width;
            }
        }
    }
    if !has_content {
        return 1;
    }
    if row_width > 0 {
        rows += 1;
    }
    rows.max(1)
}

/// Compute mapping from visual rows to logical lines for wrapped text
fn compute_wrap_mapping(lines: &[Line], width: usize, first_logical_line: usize) -> WrapMapping {
    let mut visual_to_logical = Vec::new();

    if width == 0 {
        return WrapMapping { visual_to_logical };
    }

    for (line_offset, line) in lines.iter().enumerate() {
        let logical_line_idx = first_logical_line + line_offset;

        // Get the display width of the line
        let text: String = line.spans.iter().map(|s| s.content.as_ref()).collect();
        let line_width = text.width();

        if line_width == 0 {
            // Empty line takes one visual row
            visual_to_logical.push((logical_line_idx, 0));
        } else {
            // Calculate how many visual rows this line takes
            let mut char_offset = 0;
            let chars: Vec<char> = text.chars().collect();

            while char_offset < chars.len() {
                visual_to_logical.push((logical_line_idx, char_offset));

                // Find how many chars fit in this row
                let mut row_width = 0;
                let mut chars_in_row = 0;
                for &ch in &chars[char_offset..] {
                    let ch_width = unicode_width::UnicodeWidthChar::width(ch).unwrap_or(1);
                    if row_width + ch_width > width {
                        break;
                    }
                    row_width += ch_width;
                    chars_in_row += 1;
                }

                // At least one char per row (handles wide chars > width)
                if chars_in_row == 0 {
                    chars_in_row = 1;
                }

                char_offset += chars_in_row;
            }
        }
    }

    WrapMapping { visual_to_logical }
}

/// Apply horizontal scroll to a line by dropping chars from the left
fn apply_horizontal_scroll(line: Line, h_scroll: usize) -> Line {
    // Convert to char-by-char with styles
    let chars_with_style: Vec<(char, Style)> = line.spans
        .into_iter()
        .flat_map(|span| {
            let style = span.style;
            span.content.chars().map(move |ch| (ch, style)).collect::<Vec<_>>()
        })
        .collect();

    // Skip h_scroll chars
    let visible_chars: Vec<(char, Style)> = chars_with_style
        .into_iter()
        .skip(h_scroll)
        .collect();

    rebuild_line_from_chars(visible_chars)
}

/// Apply selection highlighting to lines, preserving existing styling.
/// When no selection is active, returns None (callers should use original lines).
/// When active, returns Some with only the affected lines modified.
pub fn apply_selection<'a>(lines: &[Line<'a>], selection: &TextSelection) -> Option<Vec<Line<'static>>> {
    if !selection.is_active() {
        return None;
    }

    Some(lines
        .iter()
        .enumerate()
        .map(|(line_idx, line)| apply_selection_to_line(line.clone(), line_idx, selection))
        .collect())
}

/// Convert a Line to owned (static lifetime)
fn line_to_owned(line: Line) -> Line<'static> {
    let spans: Vec<Span<'static>> = line.spans
        .into_iter()
        .map(|span| Span::styled(span.content.to_string(), span.style))
        .collect();
    Line::from(spans)
}

/// Apply selection highlighting to a single line
fn apply_selection_to_line(line: Line, line_idx: usize, selection: &TextSelection) -> Line<'static> {
    let Some(((start_line, start_col), (end_line, end_col))) = selection.range() else {
        return line_to_owned(line);
    };

    // Check if this line is in selection range
    if line_idx < start_line || line_idx > end_line {
        return line_to_owned(line);
    }

    // Calculate selection columns for this line
    let sel_start = if line_idx == start_line { start_col } else { 0 };
    let sel_end = if line_idx == end_line { end_col } else { usize::MAX };

    // Convert to char-by-char with styles
    let chars_with_style: Vec<(char, Style)> = line.spans
        .into_iter()
        .flat_map(|span| {
            let style = span.style;
            span.content.chars().map(move |ch| (ch, style)).collect::<Vec<_>>()
        })
        .collect();

    // Apply selection background while preserving existing style
    let modified: Vec<(char, Style)> = chars_with_style
        .into_iter()
        .enumerate()
        .map(|(col, (ch, style))| {
            if col >= sel_start && col < sel_end {
                (ch, style.bg(Color::LightBlue))
            } else {
                (ch, style)
            }
        })
        .collect();

    rebuild_line_from_chars(modified)
}

/// Rebuild a Line from character-style pairs by grouping consecutive same-styled chars
fn rebuild_line_from_chars(chars: Vec<(char, Style)>) -> Line<'static> {
    if chars.is_empty() {
        return Line::from("");
    }

    let mut spans = Vec::new();
    let mut current_text = String::new();
    let mut current_style: Option<Style> = None;

    for (ch, style) in chars {
        if Some(style) == current_style {
            current_text.push(ch);
        } else {
            if !current_text.is_empty() {
                spans.push(Span::styled(
                    std::mem::take(&mut current_text),
                    current_style.unwrap_or_default(),
                ));
            }
            current_text.push(ch);
            current_style = Some(style);
        }
    }

    if !current_text.is_empty() {
        spans.push(Span::styled(current_text, current_style.unwrap_or_default()));
    }

    Line::from(spans)
}
