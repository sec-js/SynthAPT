//! Unified mouse selection handling and clipboard utilities for TUI panes

use std::io::Write;

use ratatui::crossterm::event::{MouseButton, MouseEvent, MouseEventKind};

use crate::tui::text::{find_word_boundaries, PaneOutputInfo, TextSelection};

/// Result of handling a mouse event for selection
pub enum SelectionResult {
    /// No action needed
    None,
    /// Text was selected and should be copied
    Copy(String),
    /// Scroll up by this amount
    ScrollUp(usize),
    /// Scroll down by this amount
    ScrollDown(usize),
}

/// Handle mouse events for text selection in a pane.
///
/// Returns what action to take (copy text, scroll, or nothing).
pub fn handle_selection_mouse<F>(
    selection: &mut TextSelection,
    output_info: Option<&PaneOutputInfo>,
    mouse: MouseEvent,
    get_line_text: F,
) -> SelectionResult
where
    F: Fn(usize) -> Option<String>,
{
    match mouse.kind {
        MouseEventKind::Down(MouseButton::Left) => {
            handle_mouse_down(selection, output_info, mouse.row, mouse.column, get_line_text)
        }
        MouseEventKind::Drag(MouseButton::Left) => {
            handle_mouse_drag(selection, output_info, mouse.row, mouse.column)
        }
        MouseEventKind::Up(MouseButton::Left) => handle_mouse_up(selection, get_line_text),
        MouseEventKind::ScrollUp => SelectionResult::ScrollUp(3),
        MouseEventKind::ScrollDown => SelectionResult::ScrollDown(3),
        _ => SelectionResult::None,
    }
}

fn handle_mouse_down<F>(
    selection: &mut TextSelection,
    output_info: Option<&PaneOutputInfo>,
    row: u16,
    col: u16,
    get_line_text: F,
) -> SelectionResult
where
    F: Fn(usize) -> Option<String>,
{
    let Some(info) = output_info else {
        return SelectionResult::None;
    };

    if row < info.area.y
        || row >= info.area.y + info.area.height
        || col < info.area.x
        || col >= info.area.x + info.area.width
    {
        selection.clear();
        return SelectionResult::None;
    }

    let visual_row = (row - info.area.y) as usize;
    let visual_col = (col - info.area.x) as usize;

    let (line_idx, char_offset) = info.wrap_mapping.visual_to_logical_pos(visual_row, visual_col);
    let char_col = char_offset + info.h_scroll;
    let click_pos = (line_idx, char_col);
    let now = std::time::Instant::now();

    let is_double_click = selection.last_click_time.map_or(false, |t| {
        now.duration_since(t).as_millis() < 500
    }) && selection.last_click_pos == Some(click_pos);

    if is_double_click {
        if let Some(text) = get_line_text(line_idx) {
            let (word_start, word_end) = find_word_boundaries(&text, char_col);
            selection.start = Some((line_idx, word_start));
            selection.end = Some((line_idx, word_end));
            selection.selecting = false;
            selection.last_click_time = None;
            selection.last_click_pos = None;

            if word_start < word_end && word_end <= text.len() {
                let chars: Vec<char> = text.chars().collect();
                let selected: String = chars[word_start..word_end].iter().collect();
                if !selected.is_empty() {
                    return SelectionResult::Copy(selected);
                }
            }
        }
    } else {
        selection.start = Some(click_pos);
        selection.end = Some(click_pos);
        selection.selecting = true;
        selection.last_click_time = Some(now);
        selection.last_click_pos = Some(click_pos);
    }

    SelectionResult::None
}

fn handle_mouse_drag(
    selection: &mut TextSelection,
    output_info: Option<&PaneOutputInfo>,
    row: u16,
    col: u16,
) -> SelectionResult {
    let Some(info) = output_info else {
        return SelectionResult::None;
    };

    if !selection.selecting {
        return SelectionResult::None;
    }

    let clamped_row = row.max(info.area.y).min(info.area.y + info.area.height.saturating_sub(1));
    let clamped_col = col.max(info.area.x).min(info.area.x + info.area.width.saturating_sub(1));

    let visual_row = (clamped_row - info.area.y) as usize;
    let visual_col = (clamped_col - info.area.x) as usize;

    let (line_idx, char_offset) = info.wrap_mapping.visual_to_logical_pos(visual_row, visual_col);
    selection.end = Some((line_idx, char_offset + info.h_scroll));

    SelectionResult::None
}

fn handle_mouse_up<F>(selection: &mut TextSelection, get_line_text: F) -> SelectionResult
where
    F: Fn(usize) -> Option<String>,
{
    if !selection.selecting {
        return SelectionResult::None;
    }

    selection.selecting = false;

    if let Some(text) = get_selected_text(selection, get_line_text) {
        if !text.is_empty() {
            return SelectionResult::Copy(text);
        }
    }

    SelectionResult::None
}

/// Extract selected text from a selection range using a line-text getter.
pub fn get_selected_text<F>(selection: &TextSelection, get_line_text: F) -> Option<String>
where
    F: Fn(usize) -> Option<String>,
{
    let (start, end) = match (selection.start, selection.end) {
        (Some(s), Some(e)) => if s <= e { (s, e) } else { (e, s) },
        _ => return None,
    };

    if start == end {
        return None;
    }

    let mut result = String::new();
    for line_idx in start.0..=end.0 {
        if let Some(line) = get_line_text(line_idx) {
            let chars: Vec<char> = line.chars().collect();
            let line_start = if line_idx == start.0 { start.1 } else { 0 };
            let line_end = if line_idx == end.0 { end.1 } else { chars.len() };
            let line_start = line_start.min(chars.len());
            let line_end = line_end.min(chars.len());
            if line_start < line_end {
                result.extend(chars[line_start..line_end].iter());
            }
            if line_idx < end.0 {
                result.push('\n');
            }
        }
    }

    if result.is_empty() { None } else { Some(result) }
}

/// Apply a SelectionResult — copy text to clipboard and return scroll amount if any.
pub fn apply_selection_result(result: SelectionResult) -> Option<usize> {
    match result {
        SelectionResult::Copy(text) => {
            copy_to_clipboard(&text);
            None
        }
        SelectionResult::ScrollUp(amount) => Some(amount),
        SelectionResult::ScrollDown(amount) => Some(amount),
        SelectionResult::None => None,
    }
}

/// Copy text to clipboard using the OSC 52 terminal escape sequence.
pub fn copy_to_clipboard(text: &str) {
    let encoded = base64_encode(text);
    let _ = std::io::stdout().write_all(format!("\x1b]52;c;{}\x07", encoded).as_bytes());
    let _ = std::io::stdout().flush();
}

fn base64_encode(input: &str) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let bytes = input.as_bytes();
    let mut result = String::new();
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0] as usize;
        let b1 = chunk.get(1).copied().unwrap_or(0) as usize;
        let b2 = chunk.get(2).copied().unwrap_or(0) as usize;
        result.push(ALPHABET[b0 >> 2] as char);
        result.push(ALPHABET[((b0 & 0x03) << 4) | (b1 >> 4)] as char);
        if chunk.len() > 1 {
            result.push(ALPHABET[((b1 & 0x0f) << 2) | (b2 >> 6)] as char);
        } else {
            result.push('=');
        }
        if chunk.len() > 2 {
            result.push(ALPHABET[b2 & 0x3f] as char);
        } else {
            result.push('=');
        }
    }
    result
}
