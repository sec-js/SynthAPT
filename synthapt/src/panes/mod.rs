use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Style},
    text::{Line, Span, Text},
    widgets::{Block, Borders, Paragraph},
    Frame,
};
use serde_json;

use common::tui::panes::{apply_selection, ScrollablePane, WrapMapping};
use common::tui::text::PaneOutputInfo;
use common::tui::theme;

use crate::message::PaneId;
use crate::model::{AgentMessage, AgentTab, CanvasState, DebugState, DebugViewState, FieldValue, LogLevel, MessageRole, Model};

/// Render the agent pane (with Chat / Debug tabs)
pub fn render_agent_pane(
    model: &mut Model,
    frame: &mut Frame,
    pane_id: PaneId,
    area: Rect,
    _focused: bool,
    border_color: Color,
) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(border_color))
        .title(" Agent ");

    let inner = block.inner(area);
    frame.render_widget(block, area);

    if inner.height < 3 {
        return;
    }

    // Split: 1-line tab bar + content
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(1), Constraint::Min(0)])
        .split(inner);

    let tab_bar_area = chunks[0];
    let content_area = chunks[1];

    // Determine active tab
    let active_tab = model.agent_states.entry(pane_id).or_default().active_tab;

    // Render tab bar
    let tabs = [(AgentTab::Chat, " Chat "), (AgentTab::Debug, " Debug ")];
    let mut x = tab_bar_area.x;
    for (tab, label) in &tabs {
        let width = label.len() as u16;
        if x + width > tab_bar_area.x + tab_bar_area.width {
            break;
        }
        let tab_rect = Rect { x, y: tab_bar_area.y, width, height: 1 };
        let style = if *tab == active_tab {
            Style::default().fg(theme::BG).bg(theme::CYAN)
        } else {
            Style::default().fg(theme::DARK_GRAY)
        };
        frame.render_widget(Paragraph::new(*label).style(style), tab_rect);
        model.tab_areas.push((pane_id, *tab, tab_rect));
        x += width;
    }

    // Fill remainder of tab bar with divider
    if x < tab_bar_area.x + tab_bar_area.width {
        let rest = Rect {
            x,
            y: tab_bar_area.y,
            width: tab_bar_area.x + tab_bar_area.width - x,
            height: 1,
        };
        frame.render_widget(
            Paragraph::new("─".repeat(rest.width as usize))
                .style(Style::default().fg(theme::DARK_GRAY)),
            rest,
        );
    }

    match active_tab {
        AgentTab::Chat => render_chat_view(model, frame, pane_id, content_area),
        AgentTab::Debug => {
            let view_state = model.debug_view_states.entry(pane_id).or_default();
            let output_info = render_debug_view(&model.debug_state, view_state, frame, content_area);
            model.pane_output_info.insert(pane_id, output_info);
        }
    }
}

/// Build rendered lines from agent messages
fn build_message_lines(messages: &[AgentMessage], error: &Option<String>) -> Vec<Line<'static>> {
    const SPINNER: &[char] = &['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];
    let mut lines: Vec<Line> = Vec::new();

    if let Some(err) = error {
        lines.push(Line::from(vec![
            Span::styled("[error] ", Style::default().fg(theme::RED)),
            Span::raw(err.clone()),
        ]));
        lines.push(Line::raw(""));
    }

    for msg in messages {
        match msg.role {
            MessageRole::User => {
                for (i, line) in msg.content.lines().enumerate() {
                    if i == 0 {
                        lines.push(Line::from(vec![
                            Span::styled("> ", Style::default().fg(theme::CYAN)),
                            Span::raw(line.to_string()),
                        ]));
                    } else {
                        lines.push(Line::from(vec![
                            Span::raw("  "),
                            Span::raw(line.to_string()),
                        ]));
                    }
                }
            }
            MessageRole::Assistant => {
                lines.push(Line::from(Span::styled(
                    "[agent]",
                    Style::default().fg(theme::GREEN),
                )));
                for line in msg.content.lines() {
                    lines.push(Line::raw(line.to_string()));
                }
            }
            MessageRole::Tool => {
                lines.push(Line::from(Span::styled(
                    "[tool]",
                    Style::default().fg(theme::YELLOW),
                )));
                for line in msg.content.lines() {
                    lines.push(Line::raw(line.to_string()));
                }
            }
        }
        lines.push(Line::raw(""));
    }

    lines
}

fn render_chat_view(model: &mut Model, frame: &mut Frame, pane_id: PaneId, area: Rect) {
    if area.height < 2 {
        return;
    }

    let focused = model.focused == pane_id;

    let state = model.agent_states.entry(pane_id).or_default();
    let msg_count = state.messages.len();

    // Rebuild cached lines only when messages change
    if state.cached_msg_count != msg_count {
        state.cached_lines = build_message_lines(&state.messages, &state.error);
        state.cached_msg_count = msg_count;
    }

    let loading = state.loading;
    let spinner_frame = state.spinner_frame;
    let scroll = if state.auto_scroll { 0 } else { state.scroll };
    let input_text = state.input.clone();
    let cursor_pos = state.cursor_pos;
    let selection = state.selection.clone();

    // Append spinner line when loading
    let combined: Vec<Line>;
    let render_lines: &[Line] = if loading {
        const SPINNER: &[char] = &['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];
        let spin = SPINNER[spinner_frame % SPINNER.len()];
        let spinner_line = Line::from(vec![
            Span::styled(format!("{} ", spin), Style::default().fg(theme::GREEN)),
            Span::styled("thinking...", Style::default().fg(theme::DARK_GRAY)),
        ]);
        combined = state.cached_lines.iter().cloned()
            .chain(std::iter::once(spinner_line))
            .collect();
        &combined
    } else {
        &state.cached_lines
    };

    // Apply selection highlighting
    let selected;
    let final_lines: &[Line] = if let Some(sel_lines) = apply_selection(render_lines, &selection) {
        selected = sel_lines;
        &selected
    } else {
        render_lines
    };

    // Calculate wrapped input height
    let prompt = "> ";
    let full_input = format!("{}{}", prompt, input_text);
    let input_width = area.width as usize;
    let input_height = calculate_wrapped_height(&full_input, input_width).max(1) as u16;
    let input_height = input_height.min(area.height / 2);
    let output_height = area.height.saturating_sub(input_height);

    let output_area = Rect { x: area.x, y: area.y, width: area.width, height: output_height };
    let input_area = Rect { x: area.x, y: area.y + output_height, width: area.width, height: input_height };

    let result = ScrollablePane::new(final_lines)
        .scroll_offset(scroll)
        .wrap(true)
        .render(frame, output_area);

    // Update scroll if clamped
    let clamped = result.clamped_offset;
    let state = model.agent_states.entry(pane_id).or_default();
    state.scroll = clamped;

    model.pane_output_info.insert(pane_id, PaneOutputInfo {
        area: output_area,
        first_visible: result.first_visible,
        wrap_mapping: result.wrap_mapping,
        h_scroll: 0,
    });

    // Render input with character-by-character cursor
    let prompt_len = prompt.chars().count();
    let cursor_abs = prompt_len + input_text[..cursor_pos.min(input_text.len())].chars().count();

    // Build visual lines accounting for wrapping
    let chars: Vec<char> = full_input.chars().collect();
    let wrap_width = input_area.width as usize;
    let mut visual_lines: Vec<(usize, String)> = Vec::new(); // (start_char_idx, line_content)
    let mut char_idx = 0usize;
    let mut col = 0usize;
    let mut current_line = String::new();
    let mut line_start = 0usize;

    while char_idx < chars.len() {
        let ch = chars[char_idx];
        current_line.push(ch);
        col += 1;
        char_idx += 1;
        if col >= wrap_width {
            visual_lines.push((line_start, current_line.clone()));
            current_line.clear();
            col = 0;
            line_start = char_idx;
        }
    }
    if !current_line.is_empty() || visual_lines.is_empty() {
        visual_lines.push((line_start, current_line));
    }

    for (y, (start_idx, line_content)) in visual_lines.iter().enumerate() {
        if y as u16 >= input_area.height {
            break;
        }
        let line_char_count = line_content.chars().count();
        let mut spans = Vec::new();

        for (i, ch) in line_content.chars().enumerate() {
            let abs_pos = start_idx + i;
            if focused && abs_pos == cursor_abs {
                spans.push(Span::styled(ch.to_string(), Style::default().bg(ratatui::style::Color::White).fg(ratatui::style::Color::Black)));
            } else if abs_pos < prompt_len {
                spans.push(Span::styled(ch.to_string(), Style::default().fg(theme::CYAN)));
            } else {
                spans.push(Span::styled(ch.to_string(), Style::default().fg(theme::FG)));
            }
        }
        // Cursor at end of this line
        if focused && cursor_abs == start_idx + line_char_count {
            spans.push(Span::styled(" ", Style::default().bg(ratatui::style::Color::White).fg(ratatui::style::Color::Black)));
        }

        frame.render_widget(
            Paragraph::new(Line::from(spans)),
            Rect { x: input_area.x, y: input_area.y + y as u16, width: input_area.width, height: 1 },
        );
    }
}

fn calculate_wrapped_height(text: &str, width: usize) -> usize {
    if width == 0 || text.is_empty() {
        return 1;
    }
    let mut lines = 0usize;
    let mut col = 0usize;
    for ch in text.chars() {
        col += 1;
        if col >= width {
            lines += 1;
            col = 0;
        }
        let _ = ch;
    }
    if col > 0 || lines == 0 { lines += 1; }
    lines
}

fn render_debug_view(
    debug_state: &DebugState,
    view_state: &mut DebugViewState,
    frame: &mut Frame,
    area: Rect,
) -> PaneOutputInfo {
    let empty_info = PaneOutputInfo {
        area,
        first_visible: 0,
        wrap_mapping: WrapMapping::default(),
        h_scroll: 0,
    };

    if debug_state.entries.is_empty() {
        let placeholder = Paragraph::new("No debug messages")
            .style(Style::default().fg(theme::DARK_GRAY));
        frame.render_widget(placeholder, area);
        return empty_info;
    }

    let total = debug_state.entries.len();
    let visible_h = area.height as usize;
    let end = total.saturating_sub(view_state.scroll);
    let start = end.saturating_sub(visible_h);

    let lines: Vec<Line> = debug_state.entries[start..end]
        .iter()
        .map(|e| {
            let (prefix, color) = match e.level {
                LogLevel::Debug => ("[DBG]", theme::DARK_GRAY),
                LogLevel::Info  => ("[INF]", theme::CYAN),
                LogLevel::Warn  => ("[WRN]", theme::YELLOW),
                LogLevel::Error => ("[ERR]", theme::RED),
            };
            Line::from(vec![
                Span::styled(prefix, Style::default().fg(color)),
                Span::raw(" "),
                Span::styled(e.message.clone(), Style::default().fg(theme::FG)),
            ])
        })
        .collect();

    // Build 1:1 wrap mapping (no line-wrapping in debug view)
    let wrap_mapping = WrapMapping {
        visual_to_logical: (0..lines.len()).map(|i| (start + i, 0)).collect(),
    };

    let output_info = PaneOutputInfo { area, first_visible: start, wrap_mapping, h_scroll: 0 };

    // Apply selection highlighting
    let selected;
    let final_lines: &[Line] = if let Some(sel_lines) = apply_selection(&lines, &view_state.selection) {
        selected = sel_lines;
        &selected
    } else {
        &lines
    };

    frame.render_widget(Paragraph::new(Text::from(final_lines.to_vec())), area);
    output_info
}

/// Render the canvas pane
pub fn render_canvas_pane(
    model: &mut Model,
    frame: &mut Frame,
    pane_id: PaneId,
    area: Rect,
    focused: bool,
    border_color: Color,
) {
    model.canvas_states.entry(pane_id).or_insert_with(CanvasState::new);

    let zoom = model.canvas_states[&pane_id].canvas.zoom;
    let focus_indicator = if focused { " [*]" } else { "" };
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(border_color))
        .title(format!(" Canvas | {:.1}x{} ", zoom, focus_indicator));

    // Split the block's inner area: canvas above, 1-row hint bar at bottom
    let inner = block.inner(area);
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(1), Constraint::Length(1)])
        .split(inner);
    let canvas_inner = chunks[0];
    let hint_area = chunks[1];

    frame.render_widget(block, area);

    // Hint bar — all dark gray, keys bold
    let hints = [
        ("n", "new playbook"),
        ("o", "open playbook"),
        ("g", "generate payload"),
        ("i", "insert node"),
        ("t", "new task set"),
    ];
    let mut spans: Vec<Span> = Vec::new();
    for (i, (key, label)) in hints.iter().enumerate() {
        if i > 0 {
            spans.push(Span::styled("  ", Style::default().fg(theme::DARK_GRAY)));
        }
        spans.push(Span::styled(
            *key,
            Style::default().fg(theme::DARK_GRAY).add_modifier(ratatui::style::Modifier::BOLD),
        ));
        spans.push(Span::styled(
            format!(" {}", label),
            Style::default().fg(theme::DARK_GRAY),
        ));
    }
    frame.render_widget(Paragraph::new(Line::from(spans)), hint_area);

    let has_shapes = model
        .canvas_states
        .get(&pane_id)
        .map(|s| !s.shapes.is_empty())
        .unwrap_or(false);

    if !has_shapes {
        let placeholder = Paragraph::new("No playbook loaded. Press n to create or o to open.")
            .style(Style::default().fg(theme::DARK_GRAY));
        frame.render_widget(placeholder, canvas_inner);
        return;
    }

    // Pass a borderless block so the canvas fills canvas_inner exactly
    let state = model.canvas_states.get_mut(&pane_id).unwrap();
    state.canvas.render_layered(
        frame,
        canvas_inner,
        Block::default(),
        &state.shapes,
        &state.connectors,
    );
}

/// Build the colored JSON lines for the detail pane (shared with mouse handler for copy).
pub fn detail_json_lines(model: &Model) -> Vec<Line<'static>> {
    let json_text = match model.selected_node {
        Some((canvas_pane_id, shape_id)) => {
            let pb_ref = model.canvas_states.get(&canvas_pane_id)
                .and_then(|s| s.shape_refs.get(&shape_id).cloned());
            match pb_ref {
                Some(crate::model::PlaybookRef::Task { set_id, index }) => {
                    model.playbook.as_ref()
                        .and_then(|pb| pb.task_sets.get(&set_id))
                        .and_then(|tasks| tasks.get(index))
                        .and_then(|task| serde_json::to_value(task).ok())
                        .and_then(|v| serde_json::to_string_pretty(&v).ok())
                        .unwrap_or_default()
                }
                Some(crate::model::PlaybookRef::TaskSetLabel { set_id }) => {
                    model.playbook.as_ref()
                        .and_then(|pb| pb.task_sets.get(&set_id))
                        .and_then(|tasks| serde_json::to_value(tasks).ok())
                        .and_then(|v| serde_json::to_string_pretty(&v).ok())
                        .unwrap_or_default()
                }
                _ => model.playbook.as_ref()
                    .and_then(|pb| serde_json::to_value(pb).ok())
                    .and_then(|v| serde_json::to_string_pretty(&v).ok())
                    .unwrap_or_default(),
            }
        }
        None => model.playbook.as_ref()
            .and_then(|pb| serde_json::to_value(pb).ok())
            .and_then(|v| serde_json::to_string_pretty(&v).ok())
            .unwrap_or_else(|| "No playbook loaded".to_string()),
    };

    json_text.lines().map(colorize_json_line).collect()
}

/// Colorize a single line of pretty-printed JSON into styled spans.
fn colorize_json_line(line: &str) -> Line<'static> {
    let trimmed = line.trim_start();
    let indent = &line[..line.len() - trimmed.len()];
    let mut spans: Vec<Span<'static>> = vec![Span::raw(indent.to_string())];

    // Structural-only lines: }, ], },  ], etc.
    if matches!(trimmed, "{" | "}" | "[" | "]" | "}," | "]," | "{}," | "{}") {
        spans.push(Span::styled(trimmed.to_string(), Style::default().fg(theme::DARK_GRAY)));
        return Line::from(spans);
    }

    // Key: "foo": ...
    if let Some(rest) = trimmed.strip_prefix('"') {
        if let Some(key_end) = rest.find('"') {
            let key = &rest[..key_end];
            let after_key = &rest[key_end + 1..]; // starts with `": ` or `"`

            if let Some(value_part) = after_key.strip_prefix(": ") {
                // It's a key-value pair
                spans.push(Span::styled(format!("\"{}\"", key), Style::default().fg(theme::CYAN)));
                spans.push(Span::styled(": ", Style::default().fg(theme::DARK_GRAY)));
                spans.extend(colorize_json_value(value_part));
                return Line::from(spans);
            }
        }
    }

    // Array element or bare value
    spans.extend(colorize_json_value(trimmed));
    Line::from(spans)
}

/// Colorize a JSON value fragment (the RHS of a key, or an array element).
fn colorize_json_value(s: &str) -> Vec<Span<'static>> {
    // Strip trailing comma for color matching, re-add after
    let (core, comma) = if s.ends_with(',') {
        (&s[..s.len() - 1], ",")
    } else {
        (s, "")
    };

    let comma_span = || Span::styled(",".to_string(), Style::default().fg(theme::DARK_GRAY));

    // String
    if core.starts_with('"') && core.ends_with('"') {
        let mut spans = vec![Span::styled(core.to_string(), Style::default().fg(theme::GREEN))];
        if !comma.is_empty() { spans.push(comma_span()); }
        return spans;
    }
    // null
    if core == "null" {
        let mut spans = vec![Span::styled("null".to_string(), Style::default().fg(theme::RED))];
        if !comma.is_empty() { spans.push(comma_span()); }
        return spans;
    }
    // bool
    if core == "true" || core == "false" {
        let mut spans = vec![Span::styled(core.to_string(), Style::default().fg(theme::PURPLE))];
        if !comma.is_empty() { spans.push(comma_span()); }
        return spans;
    }
    // number
    if core.chars().next().map(|c| c.is_ascii_digit() || c == '-').unwrap_or(false) {
        let mut spans = vec![Span::styled(core.to_string(), Style::default().fg(theme::YELLOW))];
        if !comma.is_empty() { spans.push(comma_span()); }
        return spans;
    }
    // structural ({, [, {}, [])
    if matches!(core, "{" | "[" | "{}" | "[]") {
        let mut spans = vec![Span::styled(core.to_string(), Style::default().fg(theme::DARK_GRAY))];
        if !comma.is_empty() { spans.push(comma_span()); }
        return spans;
    }

    // Fallback
    vec![Span::styled(s.to_string(), Style::default().fg(theme::FG))]
}

pub fn render_detail_pane(
    model: &mut Model,
    frame: &mut Frame,
    pane_id: PaneId,
    area: Rect,
    _focused: bool,
    border_color: Color,
) {
    let title = if model.task_edit.is_some() { " Edit " } else { " Detail " };
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(border_color))
        .title(title);

    let inner = block.inner(area);
    frame.render_widget(block, area);

    if model.task_edit.is_some() {
        render_task_form(model, frame, pane_id, inner);
    } else {
        render_detail_json(model, frame, pane_id, inner);
    }
}

fn render_detail_json(model: &mut Model, frame: &mut Frame, pane_id: PaneId, inner: Rect) {
    let lines = detail_json_lines(model);
    let selection = model.detail_selection.clone();

    let selected_lines;
    let display_lines: &[Line] = if let Some(sel) = apply_selection(&lines, &selection) {
        selected_lines = sel;
        &selected_lines
    } else {
        &lines
    };

    let result = ScrollablePane::new(display_lines)
        .scroll_offset(model.detail_scroll)
        .scroll_from_top(true)
        .render(frame, inner);

    model.detail_scroll = result.clamped_offset;

    model.pane_output_info.insert(pane_id, PaneOutputInfo {
        area: inner,
        first_visible: result.first_visible,
        wrap_mapping: result.wrap_mapping,
        h_scroll: 0,
    });
}

fn render_task_form(model: &mut Model, frame: &mut Frame, pane_id: PaneId, area: Rect) {
    if area.height < 2 { return; }

    let edit = match model.task_edit.as_ref() {
        Some(e) => e,
        None => return,
    };

    // Reserve the last line for the hint bar
    let form_area = Rect { height: area.height - 1, ..area };
    let hint_area = Rect { y: area.y + area.height - 1, height: 1, ..area };

    // Determine whether any field is currently being edited
    let is_editing = edit.fields.get(edit.selected).map(|f| f.editing.is_some()).unwrap_or(false);

    let hint_text = if is_editing {
        " Enter to save · Esc to cancel"
    } else {
        " Enter to edit"
    };
    frame.render_widget(
        ratatui::widgets::Paragraph::new(hint_text)
            .style(Style::default().fg(theme::DARK_GRAY)),
        hint_area,
    );

    let op = model.playbook.as_ref()
        .and_then(|pb| pb.task_sets.get(&edit.set_id))
        .and_then(|tasks| tasks.get(edit.index))
        .and_then(|t| serde_json::to_value(t).ok())
        .and_then(|v| v.get("op").and_then(|o| o.as_str()).map(|s| s.to_string()))
        .unwrap_or_default();

    // Name column width: longest field name + 2
    let name_w = edit.fields.iter()
        .map(|f| f.name.len())
        .max()
        .unwrap_or(4)
        .max(4) + 2;

    let mut lines: Vec<Line> = vec![
        Line::from(vec![
            Span::styled("op:  ", Style::default().fg(theme::DARK_GRAY)),
            Span::styled(op, Style::default().fg(theme::CYAN)),
        ]),
        Line::from(Span::styled(
            "─".repeat(form_area.width as usize),
            Style::default().fg(theme::DARK_GRAY),
        )),
    ];

    let selected = edit.selected;

    for (i, field) in edit.fields.iter().enumerate() {
        let is_selected = i == selected;

        // Pad name to name_w
        let req_marker = if field.required { "* " } else { "  " };
        let name_str = format!("{:<width$}", field.name, width = name_w);

        let type_str = format!(" [{}]", field.type_hint);

        let req_color = if field.required { theme::RED } else { theme::DARK_GRAY };

        let mut row_spans = vec![
            Span::styled(req_marker, Style::default().fg(req_color)),
            Span::styled(name_str, Style::default().fg(theme::CYAN)),
        ];

        match (&field.value, &field.editing) {
            // Actively editing: render before / cursor-char / after as separate spans
            (_, Some(editing)) => {
                let before = editing.buffer[..editing.cursor].to_string();
                let char_bytes = editing.buffer[editing.cursor..]
                    .chars().next().map(|c| c.len_utf8()).unwrap_or(0);
                let at_cursor = if char_bytes > 0 {
                    editing.buffer[editing.cursor..editing.cursor + char_bytes].to_string()
                } else {
                    " ".to_string() // cursor past end
                };
                let after_start = editing.cursor + char_bytes;
                let after = editing.buffer[after_start..].to_string();

                if !before.is_empty() {
                    row_spans.push(Span::styled(before, Style::default().fg(theme::FG)));
                }
                row_spans.push(Span::styled(at_cursor, Style::default().fg(theme::BG).bg(theme::CYAN)));
                if !after.is_empty() {
                    row_spans.push(Span::styled(after, Style::default().fg(theme::FG)));
                }
            }
            // Bool
            (FieldValue::Bool(b), None) => {
                let (checkbox, label) = if *b { ("[x]", " true") } else { ("[ ]", " false") };
                let color = if *b { theme::CYAN } else { theme::DARK_GRAY };
                row_spans.push(Span::styled(checkbox, Style::default().fg(color)));
                row_spans.push(Span::styled(label, Style::default().fg(theme::FG)));
            }
            // Empty optional
            (FieldValue::Empty, None) => {
                row_spans.push(Span::styled("<none>", Style::default().fg(theme::DARK_GRAY)));
            }
            // Text / Int
            (FieldValue::Text(s) | FieldValue::Int(s), None) => {
                row_spans.push(Span::styled(s.clone(), Style::default().fg(theme::GREEN)));
            }
        }

        row_spans.push(Span::styled(type_str, Style::default().fg(theme::DARK_GRAY)));

        let mut line = Line::from(row_spans);
        if is_selected && field.editing.is_none() {
            line = line.style(Style::default().bg(ratatui::style::Color::DarkGray));
        }
        lines.push(line);
    }

    if edit.fields.is_empty() {
        lines.push(Line::from(Span::styled(
            "  (no parameters)",
            Style::default().fg(theme::DARK_GRAY),
        )));
    }

    // Render with scroll so long field lists are scrollable
    let result = ScrollablePane::new(&lines)
        .scroll_offset(model.detail_scroll)
        .scroll_from_top(true)
        .render(frame, form_area);

    model.detail_scroll = result.clamped_offset;

    // Store output info using form_area so mouse row-to-field mapping stays correct
    model.pane_output_info.insert(pane_id, PaneOutputInfo {
        area: form_area,
        first_visible: result.first_visible,
        wrap_mapping: result.wrap_mapping,
        h_scroll: 0,
    });
}
