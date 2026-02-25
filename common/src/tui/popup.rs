//! Generic popup overlay widgets

use ratatui::{
    layout::{Constraint, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Paragraph},
    Frame,
};

use super::theme;

/// A reusable popup overlay widget.
///
/// Renders centered on the screen with a title, message, optional options list,
/// and an optional text input field.
pub struct PopupWidget<'a> {
    pub title: &'a str,
    pub message: &'a str,
    /// Option labels to display. Empty slice = no option buttons.
    pub options: &'a [&'a str],
    /// Index of the highlighted option.
    pub selected: usize,
    /// If Some, renders a text input field: (buffer, cursor_byte_pos).
    pub input: Option<(&'a str, usize)>,
}

impl<'a> PopupWidget<'a> {
    pub fn render(self, frame: &mut Frame) {
        let area = frame.area();

        let popup_width = (area.width * 60 / 100).max(40).min(area.width.saturating_sub(4));
        let popup_height = 9.min(area.height.saturating_sub(4));
        let popup_area = centered_rect(popup_width, popup_height, area);

        frame.render_widget(Clear, popup_area);

        let block = Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(theme::YELLOW))
            .title(format!(" {} ", self.title));

        let inner = block.inner(popup_area);
        frame.render_widget(block, popup_area);

        let chunks = Layout::vertical([
            Constraint::Min(1),
            Constraint::Length(2),
        ])
        .split(inner);

        let message_para = Paragraph::new(self.message)
            .style(Style::default().fg(theme::FG));

        if let Some((buffer, cursor)) = self.input {
            let input_chunks = Layout::vertical([
                Constraint::Length(2),
                Constraint::Length(1),
            ])
            .split(chunks[0]);

            frame.render_widget(message_para, input_chunks[0]);

            let cursor = cursor.min(buffer.len());
            let before = &buffer[..cursor];
            let after = &buffer[cursor..];
            let cursor_char = after.chars().next().unwrap_or(' ');
            let after_cursor = if after.len() > cursor_char.len_utf8() {
                &after[cursor_char.len_utf8()..]
            } else {
                ""
            };

            let input_line = Line::from(vec![
                Span::raw(before),
                Span::styled(
                    cursor_char.to_string(),
                    Style::default().bg(theme::FG).fg(theme::BG),
                ),
                Span::raw(after_cursor),
            ]);

            frame.render_widget(
                Paragraph::new(input_line).style(Style::default().fg(theme::CYAN)),
                input_chunks[1],
            );

            if self.options.is_empty() {
                let hint = Paragraph::new("Enter to submit, Escape to cancel")
                    .style(Style::default().fg(theme::DARK_GRAY));
                frame.render_widget(hint, chunks[1]);
            }
        } else {
            frame.render_widget(message_para, chunks[0]);
        }

        if !self.options.is_empty() {
            let spans: Vec<Span> = self.options
                .iter()
                .enumerate()
                .flat_map(|(i, opt)| {
                    let style = if i == self.selected {
                        Style::default()
                            .fg(theme::BG)
                            .bg(theme::YELLOW)
                            .add_modifier(Modifier::BOLD)
                    } else {
                        Style::default().fg(theme::DARK_GRAY)
                    };
                    let mut s = Vec::new();
                    if i > 0 {
                        s.push(Span::raw("  "));
                    }
                    s.push(Span::styled(*opt, style));
                    s
                })
                .collect();

            let options_area = Rect {
                x: chunks[1].x,
                y: chunks[1].y + 1,
                width: chunks[1].width,
                height: 1,
            };
            frame.render_widget(Paragraph::new(Line::from(spans)), options_area);
        }
    }
}

/// A single item in a [`ListPopupWidget`].
pub struct ListItem<'a> {
    /// Primary label (e.g. op name), shown on the left.
    pub primary: &'a str,
    /// Secondary label (e.g. description), shown on the right.
    pub secondary: &'a str,
}

/// A searchable, scrollable list popup.
///
/// The caller is responsible for pre-filtering `items` based on `filter`.
/// `selected` is an index into the filtered `items` slice.
pub struct ListPopupWidget<'a> {
    pub title: &'a str,
    /// Current filter text (shown in input box).
    pub filter: &'a str,
    /// Byte-position cursor within `filter`.
    pub cursor: usize,
    /// Pre-filtered items to display.
    pub items: &'a [ListItem<'a>],
    /// Highlighted index within `items`.
    pub selected: usize,
    /// First visible item index (scroll offset).
    pub scroll: usize,
}

impl<'a> ListPopupWidget<'a> {
    pub fn render(self, frame: &mut Frame) {
        let area = frame.area();

        let popup_width = (area.width * 70 / 100).max(50).min(area.width.saturating_sub(4));
        let popup_height = (area.height * 60 / 100).max(10).min(area.height.saturating_sub(4));
        let popup_area = centered_rect(popup_width, popup_height, area);

        frame.render_widget(Clear, popup_area);

        let block = Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(theme::CYAN))
            .title(format!(" {} ", self.title));

        let inner = block.inner(popup_area);
        frame.render_widget(block, popup_area);

        // Layout: filter row, separator, list, hint
        let list_height = inner.height.saturating_sub(3) as usize;

        let chunks = Layout::vertical([
            Constraint::Length(1), // filter input
            Constraint::Length(1), // separator
            Constraint::Min(1),    // list
            Constraint::Length(1), // hint
        ])
        .split(inner);

        // Filter input with cursor
        let cursor = self.cursor.min(self.filter.len());
        let before = &self.filter[..cursor];
        let after = &self.filter[cursor..];
        let cursor_char = after.chars().next().unwrap_or(' ');
        let after_cursor = if after.len() > cursor_char.len_utf8() {
            &after[cursor_char.len_utf8()..]
        } else {
            ""
        };
        let filter_line = Line::from(vec![
            Span::styled("> ", Style::default().fg(theme::CYAN)),
            Span::raw(before),
            Span::styled(cursor_char.to_string(), Style::default().bg(theme::FG).fg(theme::BG)),
            Span::raw(after_cursor),
        ]);
        frame.render_widget(Paragraph::new(filter_line), chunks[0]);

        // Separator
        let sep = "─".repeat(inner.width as usize);
        frame.render_widget(
            Paragraph::new(sep).style(Style::default().fg(theme::DARK_GRAY)),
            chunks[1],
        );

        // List items
        let label_width = (popup_width as usize / 3).max(15).min(25);
        let scroll = self.scroll.min(self.items.len());
        let visible = &self.items[scroll..];

        for (i, item) in visible.iter().take(list_height).enumerate() {
            let idx = scroll + i;
            let row_area = Rect {
                x: chunks[2].x,
                y: chunks[2].y + i as u16,
                width: chunks[2].width,
                height: 1,
            };

            let primary_padded = format!("{:<width$}", item.primary, width = label_width);
            let avail = chunks[2].width.saturating_sub(label_width as u16 + 2) as usize;
            let secondary: String = item.secondary.chars().take(avail).collect();

            if idx == self.selected {
                let line = Line::from(vec![
                    Span::styled(
                        format!(" {}", primary_padded),
                        Style::default().fg(theme::BG).bg(theme::CYAN).add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(
                        format!(" {}", secondary),
                        Style::default().fg(theme::BG).bg(theme::CYAN),
                    ),
                ]);
                frame.render_widget(
                    Paragraph::new(line).style(Style::default().bg(theme::CYAN)),
                    row_area,
                );
            } else {
                let line = Line::from(vec![
                    Span::styled(format!(" {}", primary_padded), Style::default().fg(theme::FG)),
                    Span::styled(format!(" {}", secondary), Style::default().fg(theme::DARK_GRAY)),
                ]);
                frame.render_widget(Paragraph::new(line), row_area);
            }
        }

        // Hint
        frame.render_widget(
            Paragraph::new("↑↓ navigate   Enter confirm   Esc cancel")
                .style(Style::default().fg(theme::DARK_GRAY)),
            chunks[3],
        );
    }
}

fn centered_rect(width: u16, height: u16, area: Rect) -> Rect {
    let x = area.x + (area.width.saturating_sub(width)) / 2;
    let y = area.y + (area.height.saturating_sub(height)) / 2;
    Rect::new(x, y, width, height)
}
