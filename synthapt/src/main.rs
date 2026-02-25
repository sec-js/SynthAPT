use std::io::stdout;
use std::time::Duration;

use clap::Parser;
use color_eyre::Result;
use crossterm::{
    event::{DisableMouseCapture, EnableMouseCapture},
    ExecutableCommand,
};
use ratatui::{
    crossterm::event::{self, Event},
    layout::{Constraint, Direction, Layout, Rect},
    style::Color,
    DefaultTerminal, Frame,
};
use common::tui::theme;

mod agent;
mod cli;
mod config;
mod hooks;
mod message;
mod model;
mod panes;
mod shortcuts;
mod update;
mod wizard;

use message::{Msg, Orientation};
use model::{LayoutNode, Model, PaneType};
use panes::{render_agent_pane, render_canvas_pane, render_detail_pane};
use update::update;

fn main() -> Result<()> {
    color_eyre::install()?;

    let args = cli::Cli::parse();

    match args.command {
        // ── export-skill subcommand: no TUI ────────────────────────────
        Some(cli::Command::ExportSkill { output }) => {
            let out_path = output.unwrap_or_else(|| ".claude/commands/synthapt.md".to_string());
            if let Some(parent) = std::path::Path::new(&out_path).parent() {
                if !parent.as_os_str().is_empty() {
                    std::fs::create_dir_all(parent)
                        .map_err(|e| color_eyre::eyre::eyre!("Failed to create directory '{}': {}", parent.display(), e))?;
                }
            }
            let prompt = agent::get_system_prompt()
                .lines()
                .filter(|l| !l.contains("edit_playbook tool"))
                .collect::<Vec<_>>()
                .join("\n");
            std::fs::write(&out_path, &prompt)
                .map_err(|e| color_eyre::eyre::eyre!("Failed to write '{}': {}", out_path, e))?;
            println!("Wrote skill to {}", out_path);
            println!("Use /synthapt in Claude Code to design playbooks.");
        }

        // ── compile subcommand: no TUI ──────────────────────────────────
        Some(cli::Command::Compile { playbook, output, exe, dll, base }) => {
            let mode = if exe {
                cli::CompileMode::Exe
            } else if dll {
                cli::CompileMode::Dll
            } else {
                cli::CompileMode::Shellcode
            };
            cli::run_compile(
                &playbook,
                output.as_deref(),
                mode,
                base.as_deref(),
            ).map_err(|e| color_eyre::eyre::eyre!(e))?;
        }

        // ── validate subcommand: no TUI ────────────────────────────────
        Some(cli::Command::Validate { path }) => {
            let json = std::fs::read_to_string(&path)
                .map_err(|e| color_eyre::eyre::eyre!("Failed to read '{}': {}", path, e))?;
            match cli::validate_playbook(&json) {
                Ok(report) => println!("{}", report),
                Err(report) => {
                    eprintln!("{}", report);
                    std::process::exit(1);
                }
            }
        }

        // ── edit subcommand or no subcommand: launch TUI ────────────────
        cmd => {
            let initial_path = match cmd {
                Some(cli::Command::Edit { path }) => {
                    if !std::path::Path::new(&path).exists() {
                        eprintln!("error: playbook not found: {path}");
                        std::process::exit(1);
                    }
                    Some(path)
                }
                _ => None,
            };
            hooks::set_initial_path(initial_path);
            run_tui()?;
        }
    }

    Ok(())
}

fn run_tui() -> Result<()> {
    stdout().execute(EnableMouseCapture)?;
    let mut terminal = ratatui::init();

    const LOGO: &str = r#"  ▟███████████  ▜█▌          ▐█▛  ▟███▙        ▐█▌▐████████████ ▐█▌         ▐█▌
 ▐█▌            ▐█▙          ▟█▌ ▐█▛ ▝██▖      ▐█▌     ▐█▌      ▐█▌         ▐█▌
 ▐█▌             ▜█▙        ▟█▛  ▐█▌  ▝▜█▙     ▐█▌     ▐█▌      ▐█▌         ▐█▌
  ▜███████████▙   ▜██████████▛   ▐█▌    ▜█▙    ▐█▌     ▐█▌      ▐█▌         ▐█▌
             ▐█▌      ▐█▌        ▐█▌     ▝██▖  ▐█▌     ▐█▌      ▐█▌█████████▐█▌
             ▐█▌      ▐█▌        ▐█▌       ▜█▙ ▟█▌     ▐█▌      ▐█▌         ▐█▌
  ████████████▛       ▐█▌        ▐█▌        ▝███▛      ▐█▌      ▐█▌         ▐█▌

                  ▐███████▌      ▟████████████▙  ▐██████████████
                  ▟█▌    ▐█▙    ▐█▌          ▐█▌       ▐█▌
                 ▐█▛      ▜█▌   ▐█▌          ▐█▌       ▐█▌
                 ▟█▌      ▐█▙   ▐█▌          ▐█▌       ▐█▌
                ▐█▛  ████████▌  ▐█▌ ██████████▛        ▐█▌
                ▟█▌        ▐█▙  ▐█▌                    ▐█▌
               ▐█▛          ▜█▌ ▐█▌                    ▐█▌"#;

    // Show splash screen
    common::tui::splash::show_splash(&mut terminal, LOGO, "AI Malware Generation", theme::RED)?;

    let result = run(terminal);

    ratatui::restore();
    stdout().execute(DisableMouseCapture)?;
    result
}

/// Main application loop using Elm architecture
fn run(mut terminal: DefaultTerminal) -> Result<()> {
    let mut model = Model::new();

    // Trigger app initialization (loads demo.json, etc.)
    model = update(model, Msg::AppInit);

    while model.running {
        // ─────────────────────────────────────────────────────
        // VIEW: Only render when the model has changed
        // ─────────────────────────────────────────────────────
        if model.needs_redraw {
            terminal.draw(|frame| render(&mut model, frame))?;
            model.needs_redraw = false;
        }

        // ─────────────────────────────────────────────────────
        // COLLECT MESSAGES from various sources
        // ─────────────────────────────────────────────────────
        let mut messages: Vec<Msg> = vec![];

        // Poll for user input - drain all queued events to avoid drag lag
        if event::poll(Duration::from_millis(16))? {
            let mut latest_drag: Option<event::MouseEvent> = None;
            loop {
                match event::read()? {
                    Event::Key(key) => messages.push(Msg::Key(key)),
                    Event::Mouse(mouse) => {
                        if matches!(mouse.kind, event::MouseEventKind::Drag(_)) {
                            // Coalesce drag events: only keep the latest position
                            latest_drag = Some(mouse);
                        } else {
                            // Flush any pending drag before non-drag mouse event
                            if let Some(drag) = latest_drag.take() {
                                messages.push(Msg::Mouse(drag));
                            }
                            messages.push(Msg::Mouse(mouse));
                        }
                    }
                    Event::Resize(_, _) => model.needs_redraw = true,
                    _ => {}
                }
                if !event::poll(Duration::ZERO)? {
                    break;
                }
            }
            // Flush final drag event
            if let Some(drag) = latest_drag {
                messages.push(Msg::Mouse(drag));
            }
        }

        // Poll background messages
        while let Ok(msg) = model.rx.try_recv() {
            messages.push(msg);
        }

        // ─────────────────────────────────────────────────────
        // UPDATE: Process messages and check if redraw needed
        // ─────────────────────────────────────────────────────

        // Always tick for animations and toast expiry
        messages.push(Msg::Tick);

        if !messages.is_empty() {
            for msg in messages {
                model = update(model, msg);
            }
            model.needs_redraw = true;
        }
    }

    // Trigger app shutdown hook
    let _ = update(model, Msg::AppShutdown);

    Ok(())
}

/// Render the UI
fn render(model: &mut Model, frame: &mut Frame) {
    let area = frame.area();

    model.terminal_size = (area.width, area.height);

    // Clear caches before rendering
    model.pane_areas.clear();
    model.split_borders.clear();
    model.tab_areas.clear();
    model.pane_output_info.clear();

    // Render mode indicator if in pane command mode
    let in_pane_command = model.shortcut_stack.has(crate::shortcuts::ContextName::PaneCommand);

    // Render the layout tree
    render_node(model, frame, model.root.clone(), area);

    if in_pane_command {
        render_mode_indicator(frame, area, " PANE ", theme::YELLOW);
    }

    // Render toast overlay if active
    if let Some(ref toast) = model.toast {
        render_toast(frame, area, &toast.message);
    }

    // Render add-node popup if open
    if let Some(ref popup) = model.add_node_popup {
        render_add_node_popup(frame, popup);
    }

    // Render confirm-delete popup if open
    if let Some(ref state) = model.confirm_delete {
        render_confirm_delete_popup(frame, state);
    }

    // Render new-playbook popup if open
    if let Some(ref state) = model.new_playbook_popup {
        render_new_playbook_popup(frame, state);
    }

    // Render file browser if open
    if let Some(ref state) = model.file_browser {
        render_file_browser(frame, state);
    }

    // Render generate popup if open
    if let Some(ref state) = model.generate_popup {
        render_generate_popup(frame, state);
    }

    // Render first-run wizard popup (always on top)
    if let Some(ref state) = model.wizard_popup {
        render_wizard_popup(frame, state);
    }
}

/// Recursively render a layout node
fn render_node(model: &mut Model, frame: &mut Frame, node: LayoutNode, area: Rect) {
    match node {
        LayoutNode::Pane(pane_id) => {
            render_pane(model, frame, pane_id, area);
        }
        LayoutNode::Split(split_id) => {
            let split_data = model
                .splits
                .iter()
                .find(|s| s.id == split_id)
                .map(|s| (s.orientation, s.ratio, s.first.clone(), s.second.clone()));

            if let Some((orientation, ratio, first, second)) = split_data {
                let chunks = match orientation {
                    Orientation::Horizontal => Layout::default()
                        .direction(Direction::Vertical)
                        .constraints([
                            Constraint::Ratio((ratio * 100.0) as u32, 100),
                            Constraint::Ratio(((1.0 - ratio) * 100.0) as u32, 100),
                        ])
                        .split(area),
                    Orientation::Vertical => Layout::default()
                        .direction(Direction::Horizontal)
                        .constraints([
                            Constraint::Ratio((ratio * 100.0) as u32, 100),
                            Constraint::Ratio(((1.0 - ratio) * 100.0) as u32, 100),
                        ])
                        .split(area),
                };

                // Record split border for mouse resize
                let border_rect = match orientation {
                    Orientation::Horizontal => Rect {
                        x: area.x,
                        y: chunks[0].y + chunks[0].height.saturating_sub(1),
                        width: area.width,
                        height: 2,
                    },
                    Orientation::Vertical => Rect {
                        x: chunks[0].x + chunks[0].width.saturating_sub(1),
                        y: area.y,
                        width: 2,
                        height: area.height,
                    },
                };
                model.split_borders.push((split_id, orientation, border_rect, area));

                render_node(model, frame, first, chunks[0]);
                render_node(model, frame, second, chunks[1]);
            }
        }
    }
}

/// Render a single pane
fn render_pane(model: &mut Model, frame: &mut Frame, pane_id: u32, area: Rect) {
    model.pane_areas.insert(pane_id, area);

    let pane_type = model.get_pane(pane_id).map(|p| p.pane_type);
    let focused = model.focused == pane_id;
    let border_color = if focused { theme::CYAN } else { theme::DARK_GRAY };

    match pane_type {
        Some(PaneType::Agent) => render_agent_pane(model, frame, pane_id, area, focused, border_color),
        Some(PaneType::Canvas) => render_canvas_pane(model, frame, pane_id, area, focused, border_color),
        Some(PaneType::Detail) => render_detail_pane(model, frame, pane_id, area, focused, border_color),
        None => {}
    }
}

/// Render a toast notification centered at the bottom of the screen
fn render_toast(frame: &mut Frame, area: Rect, message: &str) {
    use ratatui::{style::Style, widgets::{Block, Borders, Clear, Paragraph}};

    let width = (message.len() as u16 + 4).min(area.width);
    let height = 3u16;
    let x = area.x + area.width.saturating_sub(width) / 2;
    let y = area.y + area.height.saturating_sub(height + 1);

    let toast_area = Rect { x, y, width, height };

    frame.render_widget(Clear, toast_area);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme::YELLOW))
        .style(Style::default().bg(theme::BG));
    let inner = block.inner(toast_area);
    frame.render_widget(block, toast_area);
    let text = Paragraph::new(message)
        .style(Style::default().fg(theme::YELLOW));
    frame.render_widget(text, inner);
}

/// Render a mode indicator in the top-right corner
fn render_mode_indicator(frame: &mut Frame, area: Rect, text: &str, bg_color: Color) {
    use ratatui::{style::Style, widgets::Paragraph};
    let width = text.len() as u16;
    let indicator = Paragraph::new(text)
        .style(Style::default().bg(bg_color).fg(theme::BG));

    let indicator_area = Rect {
        x: area.width.saturating_sub(width + 1),
        y: 0,
        width,
        height: 1,
    };

    frame.render_widget(indicator, indicator_area);
}

/// Render the add-node op-selection popup
fn render_add_node_popup(frame: &mut Frame, popup: &crate::model::AddNodePopupState) {
    use common::tui::metadata::{all_task_metadata, TaskMeta};
    use common::tui::popup::{ListItem, ListPopupWidget};

    let all = all_task_metadata();
    let filtered = TaskMeta::filter(all, &popup.filter);

    let items: Vec<ListItem<'_>> = filtered
        .iter()
        .map(|m| ListItem { primary: m.op, secondary: m.description })
        .collect();

    ListPopupWidget {
        title: "Add Node",
        filter: &popup.filter,
        cursor: popup.cursor,
        items: &items,
        selected: popup.selected,
        scroll: popup.scroll,
    }
    .render(frame);
}

/// Render the confirm-delete-task-set popup
fn render_confirm_delete_popup(frame: &mut Frame, state: &crate::model::ConfirmDeleteState) {
    use common::tui::popup::PopupWidget;
    let message = format!("Delete task set \"task_{}\"?\nThis cannot be undone.", state.set_id);
    PopupWidget {
        title: "Delete Task Set",
        message: &message,
        options: &["Yes, delete", "Cancel"],
        selected: state.selected,
        input: None,
    }
    .render(frame);
}

/// Render the new-playbook filename popup
fn render_new_playbook_popup(frame: &mut Frame, state: &crate::model::NewPlaybookPopupState) {
    use ratatui::{
        layout::Alignment,
        style::Style,
        widgets::{Block, Borders, Clear, Paragraph},
    };

    let area = frame.area();
    let width = 50u16.min(area.width.saturating_sub(4));
    let height = 5u16;
    let x = area.x + area.width.saturating_sub(width) / 2;
    let y = area.y + area.height.saturating_sub(height) / 2;
    let popup_area = ratatui::layout::Rect { x, y, width, height };

    frame.render_widget(Clear, popup_area);

    let block = Block::default()
        .title(" New Playbook ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme::CYAN))
        .style(Style::default().bg(theme::BG));

    let inner = block.inner(popup_area);
    frame.render_widget(block, popup_area);

    // Instruction line
    let hint = Paragraph::new("Enter filename (Enter to create, Esc to cancel):")
        .style(Style::default().fg(theme::DARK_GRAY));
    let hint_area = ratatui::layout::Rect { x: inner.x, y: inner.y, width: inner.width, height: 1 };
    frame.render_widget(hint, hint_area);

    // Input line with cursor
    let cursor_pos = state.cursor.min(state.filename.len());
    let before = &state.filename[..cursor_pos];
    let after = &state.filename[cursor_pos..];
    let input_text = format!("{before}|{after}");
    let input = Paragraph::new(input_text)
        .style(Style::default().fg(theme::FG))
        .alignment(Alignment::Left);
    let input_area = ratatui::layout::Rect {
        x: inner.x,
        y: inner.y + 2,
        width: inner.width,
        height: 1,
    };
    frame.render_widget(input, input_area);
}

/// Render the first-run setup wizard popup
fn render_wizard_popup(frame: &mut Frame, state: &crate::model::WizardPopupState) {
    use ratatui::{
        layout::Alignment,
        style::Style,
        widgets::{Block, Borders, Clear, Paragraph},
    };

    let area = frame.area();
    let width = 64u16.min(area.width.saturating_sub(4));
    let height = 9u16;
    let x = area.x + area.width.saturating_sub(width) / 2;
    let y = area.y + area.height.saturating_sub(height) / 2;
    let popup_area = ratatui::layout::Rect { x, y, width, height };

    frame.render_widget(Clear, popup_area);

    let block = Block::default()
        .title(" SynthAPT — First Run Setup ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme::CYAN))
        .style(Style::default().bg(theme::BG));

    let inner = block.inner(popup_area);
    frame.render_widget(block, popup_area);

    let lines = [
        "Enter your Claude API key to enable the AI assistant.",
        "The key is saved to ~/.config/SynthAPT/config.toml.",
        "You can also set ANTHROPIC_API_KEY in your environment.",
        "",
        "Press Enter to save   |   Esc to skip",
    ];

    for (i, line) in lines.iter().enumerate() {
        let hint = Paragraph::new(*line)
            .style(Style::default().fg(theme::FG))
            .alignment(Alignment::Left);
        let row = ratatui::layout::Rect {
            x: inner.x, y: inner.y + i as u16, width: inner.width, height: 1,
        };
        frame.render_widget(hint, row);
    }

    // Input line with cursor
    let cursor_pos = state.cursor.min(state.input.len());
    let before = &state.input[..cursor_pos];
    let after = &state.input[cursor_pos..];
    // Mask the key so it doesn't appear on screen
    let masked_before = "•".repeat(before.chars().count());
    let masked_after = "•".repeat(after.chars().count());
    let input_text = format!("{masked_before}|{masked_after}");
    let input = Paragraph::new(input_text)
        .style(Style::default().fg(theme::FG))
        .alignment(Alignment::Left);
    let input_area = ratatui::layout::Rect {
        x: inner.x,
        y: inner.y + lines.len() as u16,
        width: inner.width,
        height: 1,
    };
    frame.render_widget(input, input_area);
}

/// Render the generate-payload popup
fn render_generate_popup(frame: &mut Frame, state: &crate::model::GeneratePopupState) {
    use common::tui::popup::{ListItem, ListPopupWidget};
    use crate::update::GENERATE_OPTIONS;

    let items: Vec<ListItem<'_>> = GENERATE_OPTIONS.iter()
        .map(|(primary, secondary)| ListItem { primary, secondary })
        .collect();

    ListPopupWidget {
        title: "Generate Payload",
        filter: "",
        cursor: 0,
        items: &items,
        selected: state.selected,
        scroll: 0,
    }
    .render(frame);
}

/// Render the file browser popup
fn render_file_browser(frame: &mut Frame, state: &crate::model::FileBrowserState) {
    common::tui::file_browser::FileBrowserWidget { state }.render(frame);
}
