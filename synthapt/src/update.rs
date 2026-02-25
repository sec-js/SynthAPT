use ratatui::crossterm::event::{MouseButton, MouseEventKind};

use common::tui::selection::{copy_to_clipboard, handle_selection_mouse, SelectionResult};
use common::tui::theme;

use crate::message::{Direction, Msg, Orientation, PaneId, SplitId};
use crate::model::{AgentMessage, AgentTab, FieldEditing, FieldEditState, FieldValue, LayoutNode, MessageRole, Model, Pane, PaneType, PlaybookRef, Split, TaskEditState};

/// Main update function - processes a message and returns updated model
pub fn update(mut model: Model, msg: Msg) -> Model {
    match msg {
        Msg::Key(key) => update_key(model, key),
        Msg::Mouse(mouse) => update_mouse(model, mouse),
        Msg::Tick => update_tick(model),
        Msg::Quit => {
            model.running = false;
            model
        }

        // ─────────────────────────────────────────────────────────
        // Shortcut-generated events
        // ─────────────────────────────────────────────────────────
        Msg::EnterPaneCommand => {
            model
                .shortcut_stack
                .push(crate::shortcuts::pane_command_context());
            model
        }
        Msg::ExitPaneCommand => {
            model
                .shortcut_stack
                .pop_to(crate::shortcuts::ContextName::PaneCommand);
            model
        }
        Msg::EscapePressed => model,
        Msg::CtrlCPressed => update_ctrl_c_pressed(model),

        // Text input
        Msg::InsertChar(c) => update_insert_char(model, c),
        Msg::DeleteBack => update_delete_back(model),
        Msg::DeleteForward => update_delete_forward(model),
        Msg::CursorLeft => update_cursor_left(model),
        Msg::CursorRight => update_cursor_right(model),
        Msg::CursorHome => update_cursor_home(model),
        Msg::CursorEnd => update_cursor_end(model),
        Msg::ClearLine => update_clear_line(model),

        // Scrolling
        Msg::ScrollUp(n) => update_scroll_up(model, n),
        Msg::ScrollDown(n) => update_scroll_down(model, n),
        Msg::ScrollPageUp => update_scroll_page_up(model),
        Msg::ScrollPageDown => update_scroll_page_down(model),

        // Agent
        Msg::AgentSubmitInput => update_agent_submit_input(model),
        Msg::AgentCancel => update_agent_cancel(model),

        // Agent background events
        Msg::AgentResponse { pane_id, content, role } => {
            let state = model.agent_states.entry(pane_id).or_default();
            if state.loading {
                state.messages.push(AgentMessage { role, content });
                if state.auto_scroll {
                    state.scroll = 0;
                }
            }
            model
        }
        Msg::AgentDone { pane_id } => {
            let state = model.agent_states.entry(pane_id).or_default();
            state.loading = false;
            if model.focused == pane_id {
                model.shortcut_stack.pop_to(crate::shortcuts::ContextName::AgentLoading);
            }
            model
        }
        Msg::AgentError { pane_id, error } => {
            let state = model.agent_states.entry(pane_id).or_default();
            state.loading = false;
            state.error = Some(error);
            if model.focused == pane_id {
                model.shortcut_stack.pop_to(crate::shortcuts::ContextName::AgentLoading);
            }
            model
        }
        Msg::ApplyPlaybookJson { json } => {
            match serde_json::from_str::<common::Playbook>(&json) {
                Ok(pb) => {
                    model = clear_selection(model);
                    populate_canvas_from_playbook(&mut model, &pb);
                    model.playbook = Some(pb);
                    rebuild_cross_set_connectors(&mut model);
                    if let Some(ref path) = model.playbook_path.clone() {
                        let _ = std::fs::write(path, &json);
                    } else {
                        // No file loaded — prompt the user to name and save it
                        model = update_save_as_open(model);
                    }
                }
                Err(e) => {
                    model.debug_state.error(format!("ApplyPlaybookJson parse error: {e}"));
                }
            }
            model
        }

        // Pane command mode
        Msg::ResizeSplit { delta } => update_resize_focused_split(model, delta, false),
        Msg::ResizeSplitHorizontal { delta } => update_resize_focused_split(model, delta, true),
        Msg::ClosePane => {
            let focused = model.focused;
            update_close_pane(model, focused)
        }

        // Pane management
        Msg::Split(orientation) => update_split(model, orientation),
        Msg::Focus(pane_id) => {
            set_focus(&mut model, pane_id);
            model
        }
        Msg::FocusNext => update_focus_cycle(model, 1),
        Msg::FocusPrev => update_focus_cycle(model, -1),
        Msg::FocusDirection(dir) => update_focus_direction(model, dir),
        Msg::Close(pane_id) => update_close_pane(model, pane_id),
        Msg::Resize { split_id, delta } => update_resize_split(model, split_id, delta),
        Msg::SetPaneType { pane_id, pane_type } => {
            let old_type = model.get_pane(pane_id).map(|p| p.pane_type);
            if let Some(pane) = model.panes.iter_mut().find(|p| p.id == pane_id) {
                pane.pane_type = pane_type;
            }
            if pane_id == model.focused {
                update_shortcuts_for_focus(&mut model, old_type, Some(pane_type));
            }
            model
        }

        // Canvas
        Msg::CanvasPan { dx, dy } => {
            let pane_id = model.focused;
            if let Some(state) = model.canvas_states.get_mut(&pane_id) {
                state.canvas.pan_scaled(dx, dy);
            }
            model
        }
        Msg::CanvasZoom { delta } => {
            let pane_id = model.focused;
            if let Some(state) = model.canvas_states.get_mut(&pane_id) {
                if delta > 0.0 {
                    state.canvas.zoom_in();
                } else {
                    state.canvas.zoom_out();
                }
            }
            model
        }
        Msg::CanvasResetView => {
            let pane_id = model.focused;
            if let Some(state) = model.canvas_states.get_mut(&pane_id) {
                state.canvas.reset_view();
            }
            model
        }

        Msg::InsertAfterSelected => insert_relative_to_selected(model, 1),
        Msg::InsertBeforeSelected => insert_relative_to_selected(model, 0),

        // Canvas shape movement
        Msg::MoveShape { pane_id, shape_id, x, y } => {
            if let Some(state) = model.canvas_states.get_mut(&pane_id) {
                if let Some(shape) = state.shapes.iter_mut().find(|s| s.id == shape_id) {
                    shape.shape.set_position(x, y);
                }
            }
            model
        }

        // Task form editor
        Msg::FormFieldDown => form_field_move(model, 1),
        Msg::FormFieldUp => form_field_move(model, -1),
        Msg::FormFieldActivate => form_field_activate(model),
        Msg::FormFieldCommit => form_field_commit(model),
        Msg::FormFieldCancel => form_field_cancel(model),
        Msg::FormFieldClear => form_field_clear(model),

        // Delete
        Msg::DeleteSelected => update_delete_selected(model),
        Msg::DeleteNode { set_id, index } => update_delete_node(model, set_id, index),
        Msg::ConfirmDeleteTaskSet => update_confirm_delete_task_set(model),
        Msg::CancelDeleteTaskSet => update_cancel_delete_task_set(model),
        Msg::ConfirmDeleteSelected => update_confirm_delete_selected(model),
        Msg::ConfirmDeleteSelectPrev => {
            if let Some(ref mut s) = model.confirm_delete { s.selected = s.selected.saturating_sub(1); }
            model
        }
        Msg::ConfirmDeleteSelectNext => {
            if let Some(ref mut s) = model.confirm_delete { s.selected = (s.selected + 1) % 2; }
            model
        }

        // Add-node popup
        Msg::OpenAddNodePopup { set_id, index } => update_open_add_node_popup(model, set_id, index),
        Msg::AddNodePopupChar(c) => update_add_node_popup_char(model, c),
        Msg::AddNodePopupBackspace => update_add_node_popup_backspace(model),
        Msg::AddNodePopupMove(delta) => update_add_node_popup_move(model, delta),
        Msg::AddNodePopupConfirm => update_add_node_popup_confirm(model),
        Msg::AddNodePopupCancel => update_add_node_popup_cancel(model),

        // Generate popup
        Msg::Generate => update_generate_open(model),
        Msg::GeneratePopupMove(delta) => update_generate_move(model, delta),
        Msg::GeneratePopupConfirm => update_generate_confirm(model),
        Msg::GeneratePopupCancel => update_generate_cancel(model),

        // File browser popup
        Msg::OpenFileBrowser => update_file_browser_open(model),
        Msg::FileBrowserMove(delta) => update_file_browser_move(model, delta),
        Msg::FileBrowserEnter => update_file_browser_enter(model),
        Msg::FileBrowserUp => update_file_browser_up(model),
        Msg::FileBrowserCancel => update_file_browser_cancel(model),

        // New-playbook popup
        Msg::NewPlaybook => update_new_playbook_open(model),
        Msg::NewPlaybookPopupChar(c) => update_new_playbook_char(model, c),
        Msg::NewPlaybookPopupBackspace => update_new_playbook_backspace(model),
        Msg::NewPlaybookPopupConfirm => update_new_playbook_confirm(model),
        Msg::NewPlaybookPopupCancel => update_new_playbook_cancel(model),

        // Setup wizard popup
        Msg::WizardChar(c) => update_wizard_char(model, c),
        Msg::WizardBackspace => update_wizard_backspace(model),
        Msg::WizardSubmit => update_wizard_submit(model),
        Msg::WizardSkip => update_wizard_skip(model),

        // Playbook mutation
        Msg::AddNode { set_id, op, index } => update_add_node(model, set_id, op, index),
        Msg::AddTaskSet => update_add_task_set(model),

        // Playbook
        Msg::Save => {
            if let (Some(pb), Some(path)) = (&model.playbook, &model.playbook_path) {
                match serde_json::to_string_pretty(pb) {
                    Ok(json) => {
                        if let Err(e) = std::fs::write(path, json) {
                            model.debug_state.error(format!("Save failed ({path}): {e}"));
                        }
                    }
                    Err(e) => {
                        model.debug_state.error(format!("Serialize failed: {e}"));
                    }
                }
            }
            model
        }
        Msg::Load { path } => {
            model = clear_selection(model);
            match std::fs::read_to_string(&path) {
                Ok(json) => match serde_json::from_str::<common::Playbook>(&json) {
                    Ok(pb) => {
                        model.debug_state.info(format!("Loaded playbook: {path}"));
                        populate_canvas_from_playbook(&mut model, &pb);
                        model.playbook = Some(pb);
                        model.playbook_path = Some(path);
                        rebuild_cross_set_connectors(&mut model);
                    }
                    Err(e) => {
                        model
                            .debug_state
                            .error(format!("Parse error ({path}): {e}"));
                    }
                },
                Err(e) => {
                    model.debug_state.error(format!("Read error ({path}): {e}"));
                }
            }
            model
        }

        // Logging — append to shared debug log
        Msg::Log { level, message } => {
            model.debug_state.push(level, message);
            model
        }

        // Lifecycle hooks
        Msg::AppInit => crate::hooks::on_app_init(model),
        Msg::AppShutdown => crate::hooks::on_app_shutdown(model),
        Msg::PaneCreated { pane_id, pane_type } => {
            crate::hooks::on_pane_created(model, pane_id, pane_type)
        }
        Msg::PaneDestroyed { pane_id, pane_type } => {
            crate::hooks::on_pane_destroyed(model, pane_id, pane_type)
        }
    }
}

/// Handle key events using the shortcut stack
fn update_key(mut model: Model, key: ratatui::crossterm::event::KeyEvent) -> Model {
    use crate::shortcuts::ContextName;

    let had_pane_command = model.shortcut_stack.has(ContextName::PaneCommand);

    if let Some(msg) = model.shortcut_stack.find_action(&key) {
        model = update(model, msg);

        // Auto-exit pane command mode after any command
        if had_pane_command && model.shortcut_stack.has(ContextName::PaneCommand) {
            model.shortcut_stack.pop_to(ContextName::PaneCommand);
        }

        return model;
    }

    // No shortcut matched - if in pane command mode, exit it
    if had_pane_command {
        model.shortcut_stack.pop_to(ContextName::PaneCommand);
    }

    model
}

/// Check if the focused pane is the agent pane with the Debug tab active
fn is_debug_view(model: &Model) -> bool {
    let pane_id = model.focused;
    model.get_pane(pane_id).map(|p| p.pane_type) == Some(PaneType::Agent)
        && model.agent_states.get(&pane_id).map(|s| s.active_tab) == Some(AgentTab::Debug)
}

/// Handle mouse events
/// Compute the area of a ListPopupWidget (70%×60%) centered on the terminal.
fn list_popup_area(tw: u16, th: u16) -> ratatui::layout::Rect {
    let w = (tw * 70 / 100).max(50).min(tw.saturating_sub(4));
    let h = (th * 60 / 100).max(10).min(th.saturating_sub(4));
    let x = (tw.saturating_sub(w)) / 2;
    let y = (th.saturating_sub(h)) / 2;
    ratatui::layout::Rect::new(x, y, w, h)
}

/// Compute the area of a PopupWidget (60%×9) centered on the terminal.
fn small_popup_area(tw: u16, th: u16) -> ratatui::layout::Rect {
    let w = (tw * 60 / 100).max(40).min(tw.saturating_sub(4));
    let h = 9u16.min(th.saturating_sub(4));
    let x = (tw.saturating_sub(w)) / 2;
    let y = (th.saturating_sub(h)) / 2;
    ratatui::layout::Rect::new(x, y, w, h)
}

fn hits(rect: ratatui::layout::Rect, col: u16, row: u16) -> bool {
    col >= rect.x && col < rect.x + rect.width && row >= rect.y && row < rect.y + rect.height
}

/// If any popup is open, intercept this mouse event.
/// Returns `(model, true)` if the event was consumed, `(model, false)` otherwise.
fn handle_popup_mouse(
    mut model: Model,
    mouse: &ratatui::crossterm::event::MouseEvent,
) -> (Model, bool) {
    use ratatui::crossterm::event::MouseEventKind;
    let col = mouse.column;
    let row = mouse.row;
    let (tw, th) = model.terminal_size;

    // ── add-node popup ──────────────────────────────────────────────────────
    if model.add_node_popup.is_some() {
        let area = list_popup_area(tw, th);
        return match mouse.kind {
            MouseEventKind::ScrollUp => (update_add_node_popup_move(model, -1), true),
            MouseEventKind::ScrollDown => (update_add_node_popup_move(model, 1), true),
            MouseEventKind::Down(_) => {
                if !hits(area, col, row) {
                    return (update_add_node_popup_cancel(model), true);
                }
                // border(1) + filter(1) + separator(1) = list starts at area.y+3
                let list_y = area.y + 3;
                if row >= list_y {
                    let idx = (row - list_y) as usize;
                    if let Some(ref mut popup) = model.add_node_popup {
                        let all = common::tui::metadata::all_task_metadata();
                        let count = common::tui::metadata::TaskMeta::filter(all, &popup.filter).len();
                        let abs = popup.scroll + idx;
                        if abs < count {
                            popup.selected = abs;
                        }
                    }
                    (update_add_node_popup_confirm(model), true)
                } else {
                    (model, true)
                }
            }
            _ => (model, true),
        };
    }

    // ── generate popup ───────────────────────────────────────────────────────
    if model.generate_popup.is_some() {
        let area = list_popup_area(tw, th);
        return match mouse.kind {
            MouseEventKind::ScrollUp => (update_generate_move(model, -1), true),
            MouseEventKind::ScrollDown => (update_generate_move(model, 1), true),
            MouseEventKind::Down(_) => {
                if !hits(area, col, row) {
                    return (update_generate_cancel(model), true);
                }
                let list_y = area.y + 3;
                if row >= list_y {
                    let idx = (row - list_y) as usize;
                    let count = GENERATE_OPTIONS.len();
                    if idx < count {
                        if let Some(ref mut s) = model.generate_popup {
                            s.selected = idx;
                        }
                    }
                    (update_generate_confirm(model), true)
                } else {
                    (model, true)
                }
            }
            _ => (model, true),
        };
    }

    // ── confirm-delete popup ─────────────────────────────────────────────────
    if model.confirm_delete.is_some() {
        let area = small_popup_area(tw, th);
        return match mouse.kind {
            MouseEventKind::Down(_) => {
                if !hits(area, col, row) {
                    (update_cancel_delete_task_set(model), true)
                } else {
                    (model, true)
                }
            }
            _ => (model, true),
        };
    }

    // ── new-playbook popup ───────────────────────────────────────────────────
    if model.new_playbook_popup.is_some() {
        let w = 50u16.min(tw.saturating_sub(4));
        let h = 5u16;
        let x = (tw.saturating_sub(w)) / 2;
        let y = (th.saturating_sub(h)) / 2;
        let area = ratatui::layout::Rect::new(x, y, w, h);
        return match mouse.kind {
            MouseEventKind::Down(_) => {
                if !hits(area, col, row) {
                    (update_new_playbook_cancel(model), true)
                } else {
                    (model, true)
                }
            }
            _ => (model, true),
        };
    }

    // ── file browser ─────────────────────────────────────────────────────────
    if model.file_browser.is_some() {
        let area = list_popup_area(tw, th);
        return match mouse.kind {
            MouseEventKind::ScrollUp => (update_file_browser_move(model, -1), true),
            MouseEventKind::ScrollDown => (update_file_browser_move(model, 1), true),
            MouseEventKind::Down(_) => {
                if !hits(area, col, row) {
                    return (update_file_browser_cancel(model), true);
                }
                let list_y = area.y + 3;
                if row >= list_y {
                    let idx = (row - list_y) as usize;
                    if let Some(ref mut fb) = model.file_browser {
                        let count = fb.entries.len();
                        if idx < count {
                            fb.selected = idx;
                        }
                    }
                    (update_file_browser_enter(model), true)
                } else {
                    (model, true)
                }
            }
            _ => (model, true),
        };
    }

    (model, false)
}

fn update_mouse(mut model: Model, mouse: ratatui::crossterm::event::MouseEvent) -> Model {
    // Popups intercept all mouse input when open
    let (m, consumed) = handle_popup_mouse(model, &mouse);
    model = m;
    if consumed {
        return model;
    }

    let col = mouse.column;
    let row = mouse.row;

    match mouse.kind {
        MouseEventKind::Down(MouseButton::Left) => {
            // Check tab areas for agent pane tab switching
            let clicked_tab = model
                .tab_areas
                .iter()
                .find(|(_, _, rect)| {
                    col >= rect.x
                        && col < rect.x + rect.width
                        && row >= rect.y
                        && row < rect.y + rect.height
                })
                .map(|(pane_id, tab, _)| (*pane_id, *tab));

            if let Some((tab_pane_id, tab)) = clicked_tab {
                if tab_pane_id != model.focused {
                    set_focus(&mut model, tab_pane_id);
                }
                model
                    .agent_states
                    .entry(tab_pane_id)
                    .or_default()
                    .active_tab = tab;
                return model;
            }

            // Check split borders for resize
            let clicked_border = model
                .split_borders
                .iter()
                .find(|(_, _, rect, _)| {
                    col >= rect.x
                        && col < rect.x + rect.width
                        && row >= rect.y
                        && row < rect.y + rect.height
                })
                .map(|(split_id, _, _, _)| *split_id);

            if let Some(split_id) = clicked_border {
                model.resizing_split = Some(split_id);
                return model;
            }

            // Check pane areas for focus
            let clicked_pane = model
                .pane_areas
                .iter()
                .find(|(_, rect)| {
                    col >= rect.x
                        && col < rect.x + rect.width
                        && row >= rect.y
                        && row < rect.y + rect.height
                })
                .map(|(id, _)| *id);

            if let Some(pane_id) = clicked_pane {
                if pane_id != model.focused {
                    set_focus(&mut model, pane_id);
                }
                if is_debug_view(&model) {
                    return update_debug_mouse(model, mouse);
                }
                if model.get_pane(pane_id).map(|p| p.pane_type) == Some(PaneType::Agent) {
                    return update_agent_mouse(model, mouse);
                } else if model.get_pane(pane_id).map(|p| p.pane_type) == Some(PaneType::Detail) {
                    return update_detail_mouse(model, mouse);
                } else if model.get_pane(pane_id).map(|p| p.pane_type) == Some(PaneType::Canvas) {
                    // Collect hit info before taking mutable borrow
                    let hit = model.canvas_states.get(&pane_id).and_then(|state| {
                        let (cx, cy) = state.canvas.screen_to_canvas(col, row);
                        use common::tui::canvas::ShapeKind;
                        state.shapes.iter().rev()
                            .filter(|s| !matches!(s.shape, ShapeKind::SelectionIndicator(_)))
                            .find(|s| s.shape.contains(cx, cy))
                            .map(|s| {
                                let pos = s.shape.position();
                                let (bx, by, bw, bh) = s.shape.bounds();
                                let is_selectable = state.shape_refs.contains_key(&s.id);
                                let pb_ref = state.shape_refs.get(&s.id).cloned();
                                (s.id, cx, cy, pos.0, pos.1, bx + bw / 2.0, by + bh / 2.0, bw, bh, is_selectable, pb_ref)
                            })
                    });

                    if let Some((shape_id, cx, cy, sx, sy, ncx, ncy, nw, nh, is_selectable, pb_ref)) = hit {
                        // AddButton → open popup at end of the task set
                        if let Some(PlaybookRef::AddButton { set_id }) = pb_ref {
                            let index = model.playbook.as_ref()
                                .and_then(|pb| pb.task_sets.get(&set_id))
                                .map(|t| t.len())
                                .unwrap_or(0);
                            return update(model, crate::message::Msg::OpenAddNodePopup { set_id, index });
                        }
                        if let Some(state) = model.canvas_states.get_mut(&pane_id) {
                            state.dragging_shape = Some((shape_id, cx, cy, sx, sy));
                            state.dragging_group.clear();
                            state.dragging_group_indicator = None;
                            if let Some(PlaybookRef::TaskSetLabel { set_id }) = state.shape_refs.get(&shape_id) {
                                let set_id = set_id.clone();
                                let group: Vec<(common::tui::canvas::ShapeId, f64, f64)> = state.shape_refs.iter()
                                    .filter(|(_, r)| match r {
                                        PlaybookRef::TaskSetLabel { set_id: s }
                                        | PlaybookRef::Task { set_id: s, .. }
                                        | PlaybookRef::AddButton { set_id: s } => s == &set_id,
                                    })
                                    .filter_map(|(&sid, _)| {
                                        state.shapes.iter().find(|s| s.id == sid)
                                            .map(|s| { let p = s.shape.position(); (sid, p.0, p.1) })
                                    })
                                    .collect();
                                state.dragging_group = group;
                            }
                        }
                        if is_selectable {
                            model = set_selection(model, pane_id, shape_id, ncx, ncy, nw, nh);
                        }
                        // Capture indicator AFTER set_selection creates the new one
                        let new_sel_id = model.selection_indicator_id;
                        if let Some(state) = model.canvas_states.get_mut(&pane_id) {
                            if !state.dragging_group.is_empty() {
                                if let Some(sel_id) = new_sel_id {
                                    if let Some(sel) = state.shapes.iter().find(|s| s.id == sel_id) {
                                        if let common::tui::canvas::ShapeKind::SelectionIndicator(si) = &sel.shape {
                                            state.dragging_group_indicator = Some((sel_id, si.cx, si.cy));
                                        }
                                    }
                                }
                            }
                        }
                    } else {
                        if let Some(state) = model.canvas_states.get_mut(&pane_id) {
                            state.dragging_shape = None;
                            state.canvas.handle_mouse_event(mouse);
                        }
                        model = clear_selection(model);
                    }
                }
            }
        }
        MouseEventKind::Drag(MouseButton::Left) | MouseEventKind::Up(MouseButton::Left)
            if model.resizing_split.is_none()
                && model.get_pane(model.focused).map(|p| p.pane_type) == Some(PaneType::Agent)
                && !is_debug_view(&model) =>
        {
            return update_agent_mouse(model, mouse);
        }

        MouseEventKind::Drag(MouseButton::Left) => {
            if let Some(split_id) = model.resizing_split {
                if let Some((_, orientation, _, parent_area)) = model
                    .split_borders
                    .iter()
                    .find(|(id, _, _, _)| *id == split_id)
                    .cloned()
                {
                    if let Some(split) = model.splits.iter_mut().find(|s| s.id == split_id) {
                        match orientation {
                            Orientation::Vertical => {
                                let relative_x = col.saturating_sub(parent_area.x) as f64;
                                let ratio = relative_x / parent_area.width as f64;
                                split.ratio = ratio.clamp(0.1, 0.9);
                            }
                            Orientation::Horizontal => {
                                let relative_y = row.saturating_sub(parent_area.y) as f64;
                                let ratio = relative_y / parent_area.height as f64;
                                split.ratio = ratio.clamp(0.1, 0.9);
                            }
                        }
                    }
                }
                return model;
            }
            if is_debug_view(&model) {
                return update_debug_mouse(model, mouse);
            }
            if model.get_pane(model.focused).map(|p| p.pane_type) == Some(PaneType::Detail) {
                return update_detail_mouse(model, mouse);
            }
            let focused = model.focused;
            let sel_indicator_id = model.selection_indicator_id;
            if model.get_pane(focused).map(|p| p.pane_type) == Some(PaneType::Canvas) {
                if let Some(state) = model.canvas_states.get_mut(&focused) {
                    if let Some((shape_id, start_cx, start_cy, start_sx, start_sy)) =
                        state.dragging_shape
                    {
                        let (cx, cy) = state.canvas.screen_to_canvas(col, row);
                        let dx = cx - start_cx;
                        let dy = cy - start_cy;

                        // Group drag (TaskSetLabel): move all shapes in the set
                        if !state.dragging_group.is_empty() {
                            let group = state.dragging_group.clone();
                            for (sid, orig_x, orig_y) in group {
                                if let Some(shape) = state.shapes.iter_mut().find(|s| s.id == sid) {
                                    shape.shape.set_position(orig_x + dx, orig_y + dy);
                                }
                            }
                            // Also move the selection indicator
                            if let Some((sel_id, init_cx, init_cy)) = state.dragging_group_indicator {
                                if let Some(sel) = state.shapes.iter_mut().find(|s| s.id == sel_id) {
                                    if let common::tui::canvas::ShapeKind::SelectionIndicator(si) = &mut sel.shape {
                                        si.cx = init_cx + dx;
                                        si.cy = init_cy + dy;
                                    }
                                }
                            }
                        }

                        let new_x = start_sx + dx;
                        let new_y = start_sy + dy;
                        let mut node_center: Option<(f64, f64)> = None;
                        // Single-shape drag (or anchor update for group)
                        if state.dragging_group.is_empty() {
                            if let Some(shape) = state.shapes.iter_mut().find(|s| s.id == shape_id) {
                                shape.shape.set_position(new_x, new_y);
                                let (bx, by, bw, bh) = shape.shape.bounds();
                                node_center = Some((bx + bw / 2.0, by + bh / 2.0));
                            }
                        }
                        // Track selection indicator
                        if let (Some((ncx, ncy)), Some(sel_id)) = (node_center, sel_indicator_id) {
                            if let Some(sel) = state.shapes.iter_mut().find(|s| s.id == sel_id) {
                                if let common::tui::canvas::ShapeKind::SelectionIndicator(si) = &mut sel.shape {
                                    si.cx = ncx;
                                    si.cy = ncy;
                                }
                            }
                        }
                    } else {
                        // Pan canvas
                        state.canvas.handle_mouse_event(mouse);
                    }
                }
            }
        }
        MouseEventKind::Up(MouseButton::Left) => {
            if model.resizing_split.is_some() {
                model.resizing_split = None;
                return model;
            }
            if is_debug_view(&model) {
                return update_debug_mouse(model, mouse);
            }
            if model.get_pane(model.focused).map(|p| p.pane_type) == Some(PaneType::Detail) {
                return update_detail_mouse(model, mouse);
            }
            let focused = model.focused;
            if model.get_pane(focused).map(|p| p.pane_type) == Some(PaneType::Canvas) {
                if let Some(state) = model.canvas_states.get_mut(&focused) {
                    state.dragging_shape = None;
                    state.dragging_group.clear();
                    state.dragging_group_indicator = None;
                    state.canvas.handle_mouse_event(mouse);
                }
            }
        }
        MouseEventKind::ScrollUp | MouseEventKind::ScrollDown => {
            if is_debug_view(&model) {
                return update_debug_mouse(model, mouse);
            }
            if model.get_pane(model.focused).map(|p| p.pane_type) == Some(PaneType::Agent) {
                return update_agent_mouse(model, mouse);
            }
            if model.get_pane(model.focused).map(|p| p.pane_type) == Some(PaneType::Detail) {
                return update_detail_mouse(model, mouse);
            }
            let focused = model.focused;
            if model.get_pane(focused).map(|p| p.pane_type) == Some(PaneType::Canvas) {
                if let Some(state) = model.canvas_states.get_mut(&focused) {
                    state.canvas.handle_mouse_event(mouse);
                }
            }
        }
        _ => {}
    }

    model
}

/// Format a debug log entry as plain text for selection/copy
fn debug_entry_text(e: &crate::model::LogEntry) -> String {
    let prefix = match e.level {
        crate::model::LogLevel::Debug => "[DBG]",
        crate::model::LogLevel::Info => "[INF]",
        crate::model::LogLevel::Warn => "[WRN]",
        crate::model::LogLevel::Error => "[ERR]",
    };
    format!("{} {}", prefix, e.message)
}

/// Handle mouse events in the debug view (selection + scroll)
fn update_debug_mouse(mut model: Model, mouse: ratatui::crossterm::event::MouseEvent) -> Model {
    let pane_id = model.focused;
    let output_info = model.pane_output_info.get(&pane_id).cloned();

    let entries = &model.debug_state.entries;
    let get_line = |idx: usize| entries.get(idx).map(|e| debug_entry_text(e));

    let view_state = model.debug_view_states.entry(pane_id).or_default();
    let result = handle_selection_mouse(
        &mut view_state.selection,
        output_info.as_ref(),
        mouse,
        get_line,
    );

    match result {
        SelectionResult::Copy(text) => {
            copy_to_clipboard(&text);
        }
        SelectionResult::ScrollUp(amount) => {
            model.debug_view_states.entry(pane_id).or_default().scroll = model.debug_view_states
                [&pane_id]
                .scroll
                .saturating_add(amount);
        }
        SelectionResult::ScrollDown(amount) => {
            model.debug_view_states.entry(pane_id).or_default().scroll = model.debug_view_states
                [&pane_id]
                .scroll
                .saturating_sub(amount);
        }
        SelectionResult::None => {}
    }

    model
}

/// Handle mouse events in the detail pane (selection + scroll, or form row select)
fn update_detail_mouse(mut model: Model, mouse: ratatui::crossterm::event::MouseEvent) -> Model {
    let pane_id = model.focused;

    // Form mode: clicks select field rows; scroll still works
    if model.task_edit.is_some() {
        match mouse.kind {
            MouseEventKind::Down(MouseButton::Left) => {
                if let Some(info) = model.pane_output_info.get(&pane_id).cloned() {
                    let row = mouse.row;
                    if row >= info.area.y && row < info.area.y + info.area.height {
                        let line_idx = (row - info.area.y) as usize + info.first_visible;
                        // First 2 lines are header (op + divider)
                        if line_idx >= 2 {
                            let field_idx = line_idx - 2;
                            if let Some(ref mut edit) = model.task_edit {
                                if field_idx < edit.fields.len() {
                                    edit.selected = field_idx;
                                }
                            }
                        }
                    }
                }
            }
            MouseEventKind::ScrollUp => {
                model.detail_scroll = model.detail_scroll.saturating_sub(1);
            }
            MouseEventKind::ScrollDown => {
                model.detail_scroll = model.detail_scroll.saturating_add(1);
            }
            _ => {}
        }
        return model;
    }

    // JSON view mode: selection + scroll
    let output_info = model.pane_output_info.get(&pane_id).cloned();

    let json_lines: Vec<String> = crate::panes::detail_json_lines(&model)
        .into_iter()
        .map(|l| l.spans.iter().map(|s| s.content.as_ref()).collect())
        .collect();
    let get_line = |idx: usize| json_lines.get(idx).cloned();

    let result = handle_selection_mouse(
        &mut model.detail_selection,
        output_info.as_ref(),
        mouse,
        get_line,
    );

    match result {
        SelectionResult::Copy(text) => { copy_to_clipboard(&text); }
        SelectionResult::ScrollUp(n) => { model.detail_scroll = model.detail_scroll.saturating_sub(n); }
        SelectionResult::ScrollDown(n) => { model.detail_scroll = model.detail_scroll.saturating_add(n); }
        SelectionResult::None => {}
    }

    model
}

/// Advance time-based state (animations, toast expiry, etc.)
fn update_tick(mut model: Model) -> Model {
    for state in model.canvas_states.values_mut() {
        state.animator.tick(&mut state.shapes, &mut state.connectors);
    }
    if let Some(ref toast) = model.toast {
        if toast.is_expired() {
            model.toast = None;
        }
    }
    // Advance spinner for loading agent panes
    for state in model.agent_states.values_mut() {
        if state.loading {
            state.spinner_frame = state.spinner_frame.wrapping_add(1);
        }
    }
    model
}

/// Handle Ctrl+C (double-press to quit)
fn update_ctrl_c_pressed(mut model: Model) -> Model {
    let now = std::time::Instant::now();
    if let Some(last) = model.last_ctrl_c {
        if now.duration_since(last).as_secs_f64() < 1.0 {
            model.running = false;
            return model;
        }
    }
    model.last_ctrl_c = Some(now);
    model.toast = Some(crate::model::Toast::new(
        "Ctrl+C again to exit",
        std::time::Duration::from_secs(1),
    ));
    model
}

// ─────────────────────────────────────────────────────────────────────────────
// TEXT INPUT HANDLERS (for agent pane)
// ─────────────────────────────────────────────────────────────────────────────

fn update_insert_char(mut model: Model, c: char) -> Model {
    // Form field editing takes priority
    if let Some(ref mut edit) = model.task_edit {
        if let Some(field) = edit.fields.get_mut(edit.selected) {
            if let Some(ref mut editing) = field.editing {
                let allow = match field.type_hint {
                    "u8" | "u16" | "u32" => c.is_ascii_digit(),
                    _ => true,
                };
                if allow {
                    editing.insert(c);
                }
                return model;
            }
        }
    }
    let pane_id = model.focused;
    if model.get_pane(pane_id).map(|p| p.pane_type) == Some(PaneType::Agent) {
        let state = model.agent_states.entry(pane_id).or_default();
        let pos = state.cursor_pos.min(state.input.len());
        state.input.insert(pos, c);
        state.cursor_pos = pos + c.len_utf8();
    }
    model
}

fn update_delete_back(mut model: Model) -> Model {
    if let Some(ref mut edit) = model.task_edit {
        if let Some(field) = edit.fields.get_mut(edit.selected) {
            if let Some(ref mut editing) = field.editing {
                editing.delete_back();
                return model;
            }
        }
    }
    let pane_id = model.focused;
    if model.get_pane(pane_id).map(|p| p.pane_type) == Some(PaneType::Agent) {
        let state = model.agent_states.entry(pane_id).or_default();
        if state.cursor_pos > 0 {
            let prev = state.input[..state.cursor_pos]
                .char_indices().last().map(|(i, _)| i).unwrap_or(0);
            state.input.remove(prev);
            state.cursor_pos = prev;
        }
    }
    model
}

fn update_delete_forward(mut model: Model) -> Model {
    if let Some(ref mut edit) = model.task_edit {
        if let Some(field) = edit.fields.get_mut(edit.selected) {
            if let Some(ref mut editing) = field.editing {
                editing.delete_forward();
                return model;
            }
        }
    }
    let pane_id = model.focused;
    if model.get_pane(pane_id).map(|p| p.pane_type) == Some(PaneType::Agent) {
        let state = model.agent_states.entry(pane_id).or_default();
        let pos = state.cursor_pos;
        if pos < state.input.len() {
            state.input.remove(pos);
        }
    }
    model
}

fn update_cursor_left(mut model: Model) -> Model {
    if let Some(ref mut edit) = model.task_edit {
        if let Some(field) = edit.fields.get_mut(edit.selected) {
            if let Some(ref mut editing) = field.editing {
                editing.move_left();
                return model;
            }
        }
    }
    let pane_id = model.focused;
    if model.get_pane(pane_id).map(|p| p.pane_type) == Some(PaneType::Agent) {
        let state = model.agent_states.entry(pane_id).or_default();
        if state.cursor_pos > 0 {
            state.cursor_pos = state.input[..state.cursor_pos]
                .char_indices().last().map(|(i, _)| i).unwrap_or(0);
        }
    }
    model
}

fn update_cursor_right(mut model: Model) -> Model {
    if let Some(ref mut edit) = model.task_edit {
        if let Some(field) = edit.fields.get_mut(edit.selected) {
            if let Some(ref mut editing) = field.editing {
                editing.move_right();
                return model;
            }
        }
    }
    let pane_id = model.focused;
    if model.get_pane(pane_id).map(|p| p.pane_type) == Some(PaneType::Agent) {
        let state = model.agent_states.entry(pane_id).or_default();
        let pos = state.cursor_pos;
        if pos < state.input.len() {
            let ch = state.input[pos..].chars().next().unwrap();
            state.cursor_pos = pos + ch.len_utf8();
        }
    }
    model
}

fn update_cursor_home(mut model: Model) -> Model {
    if let Some(ref mut edit) = model.task_edit {
        if let Some(field) = edit.fields.get_mut(edit.selected) {
            if let Some(ref mut editing) = field.editing {
                editing.cursor = 0;
                return model;
            }
        }
    }
    let pane_id = model.focused;
    if model.get_pane(pane_id).map(|p| p.pane_type) == Some(PaneType::Agent) {
        let state = model.agent_states.entry(pane_id).or_default();
        state.cursor_pos = 0;
    }
    model
}

fn update_cursor_end(mut model: Model) -> Model {
    if let Some(ref mut edit) = model.task_edit {
        if let Some(field) = edit.fields.get_mut(edit.selected) {
            if let Some(ref mut editing) = field.editing {
                editing.cursor = editing.buffer.len();
                return model;
            }
        }
    }
    let pane_id = model.focused;
    if model.get_pane(pane_id).map(|p| p.pane_type) == Some(PaneType::Agent) {
        let state = model.agent_states.entry(pane_id).or_default();
        state.cursor_pos = state.input.len();
    }
    model
}

fn update_clear_line(mut model: Model) -> Model {
    if let Some(ref mut edit) = model.task_edit {
        if let Some(field) = edit.fields.get_mut(edit.selected) {
            if let Some(ref mut editing) = field.editing {
                editing.buffer.clear();
                editing.cursor = 0;
                return model;
            }
        }
    }
    let pane_id = model.focused;
    if model.get_pane(pane_id).map(|p| p.pane_type) == Some(PaneType::Agent) {
        let state = model.agent_states.entry(pane_id).or_default();
        state.input.clear();
        state.cursor_pos = 0;
    }
    model
}

// ─────────────────────────────────────────────────────────────────────────────
// SCROLL HANDLERS
// ─────────────────────────────────────────────────────────────────────────────

fn update_scroll_up(mut model: Model, n: usize) -> Model {
    let pane_id = model.focused;
    match model.get_pane(pane_id).map(|p| p.pane_type) {
        Some(PaneType::Detail) => {
            model.detail_scroll = model.detail_scroll.saturating_sub(n);
        }
        Some(PaneType::Agent) => {
            let active_tab = model.agent_states.entry(pane_id).or_default().active_tab;
            match active_tab {
                AgentTab::Chat => {
                    let state = model.agent_states.entry(pane_id).or_default();
                    state.scroll = state.scroll.saturating_add(n);
                    state.auto_scroll = false;
                }
                AgentTab::Debug => {
                    let state = model.debug_view_states.entry(pane_id).or_default();
                    state.scroll = state.scroll.saturating_add(n);
                }
            }
        }
        _ => {}
    }
    model
}

fn update_scroll_down(mut model: Model, n: usize) -> Model {
    let pane_id = model.focused;
    match model.get_pane(pane_id).map(|p| p.pane_type) {
        Some(PaneType::Detail) => {
            model.detail_scroll = model.detail_scroll.saturating_add(n);
        }
        Some(PaneType::Agent) => {
            let active_tab = model.agent_states.entry(pane_id).or_default().active_tab;
            match active_tab {
                AgentTab::Chat => {
                    let state = model.agent_states.entry(pane_id).or_default();
                    state.scroll = state.scroll.saturating_sub(n);
                    if state.scroll == 0 {
                        state.auto_scroll = true;
                    }
                }
                AgentTab::Debug => {
                    let state = model.debug_view_states.entry(pane_id).or_default();
                    state.scroll = state.scroll.saturating_sub(n);
                }
            }
        }
        _ => {}
    }
    model
}

fn update_scroll_page_up(model: Model) -> Model {
    update_scroll_up(model, 10)
}

fn update_scroll_page_down(model: Model) -> Model {
    update_scroll_down(model, 10)
}

// ─────────────────────────────────────────────────────────────────────────────
// AGENT HANDLERS
// ─────────────────────────────────────────────────────────────────────────────

fn update_agent_submit_input(mut model: Model) -> Model {
    let pane_id = model.focused;
    let state = model.agent_states.entry(pane_id).or_default();

    let content = state.input.trim().to_string();
    if content.is_empty() || state.loading {
        return model;
    }

    state.input.clear();
    state.cursor_pos = 0;
    state.error = None;
    state.messages.push(AgentMessage { role: MessageRole::User, content: content.clone() });
    state.loading = true;
    state.scroll = 0;
    state.auto_scroll = true;
    model.shortcut_stack.push(crate::shortcuts::agent_loading_context());

    let messages = state.messages.clone();
    let playbook_json = model.playbook.as_ref()
        .and_then(|pb| serde_json::to_string_pretty(pb).ok())
        .unwrap_or_else(|| "null".to_string());

    let snapshot = crate::agent::claude::AgentModelSnapshot { playbook_json };
    crate::agent::send_message_async(pane_id, messages, snapshot);

    model
}

fn update_agent_cancel(mut model: Model) -> Model {
    let pane_id = model.focused;
    let state = model.agent_states.entry(pane_id).or_default();
    if state.loading {
        state.loading = false;
        state.error = Some("Cancelled".to_string());
        model.shortcut_stack.pop_to(crate::shortcuts::ContextName::AgentLoading);
    }
    model
}

/// Handle mouse events for the agent pane (selection + scroll)
fn update_agent_mouse(mut model: Model, mouse: ratatui::crossterm::event::MouseEvent) -> Model {
    use common::tui::selection::{copy_to_clipboard, handle_selection_mouse, SelectionResult};

    let pane_id = model.focused;
    let output_info = model.pane_output_info.get(&pane_id).cloned();

    // Pre-collect line texts to avoid borrow conflict
    let line_texts: Vec<String> = {
        let state = model.agent_states.entry(pane_id).or_default();
        state.cached_lines.iter()
            .map(|line| line.spans.iter().map(|s| s.content.as_ref()).collect::<String>())
            .collect()
    };
    let get_line = |idx: usize| line_texts.get(idx).cloned();

    let state = model.agent_states.entry(pane_id).or_default();
    let result = handle_selection_mouse(&mut state.selection, output_info.as_ref(), mouse, get_line);

    match result {
        SelectionResult::Copy(text) => {
            copy_to_clipboard(&text);
        }
        SelectionResult::ScrollUp(amount) => {
            let state = model.agent_states.entry(pane_id).or_default();
            state.scroll = state.scroll.saturating_add(amount);
            state.auto_scroll = false;
        }
        SelectionResult::ScrollDown(amount) => {
            let state = model.agent_states.entry(pane_id).or_default();
            state.scroll = state.scroll.saturating_sub(amount);
            if state.scroll == 0 {
                state.auto_scroll = true;
            }
        }
        SelectionResult::None => {}
    }

    model
}

// ─────────────────────────────────────────────────────────────────────────────
// PANE MANAGEMENT
// ─────────────────────────────────────────────────────────────────────────────

/// Create a split in the focused pane
fn update_split(mut model: Model, orientation: Orientation) -> Model {
    let focused_id = model.focused;

    let new_pane_id = model.next_pane_id();
    let new_pane_type = PaneType::Agent;
    let new_pane = Pane {
        id: new_pane_id,
        pane_type: new_pane_type,
    };
    model.panes.push(new_pane);

    model = crate::hooks::on_pane_created(model, new_pane_id, new_pane_type);

    let split_id = model.next_split_id();
    let split = Split {
        id: split_id,
        orientation,
        ratio: 0.5,
        first: LayoutNode::Pane(focused_id),
        second: LayoutNode::Pane(new_pane_id),
    };

    if let LayoutNode::Pane(id) = model.root {
        if id == focused_id {
            model.root = LayoutNode::Split(split_id);
            model.splits.push(split);
            set_focus(&mut model, new_pane_id);
            return model;
        }
    }

    for existing_split in &mut model.splits {
        if let LayoutNode::Pane(id) = &existing_split.first {
            if *id == focused_id {
                existing_split.first = LayoutNode::Split(split_id);
                model.splits.push(split);
                set_focus(&mut model, new_pane_id);
                return model;
            }
        }
        if let LayoutNode::Pane(id) = &existing_split.second {
            if *id == focused_id {
                existing_split.second = LayoutNode::Split(split_id);
                model.splits.push(split);
                set_focus(&mut model, new_pane_id);
                return model;
            }
        }
    }

    model.splits.push(split);
    set_focus(&mut model, new_pane_id);
    model
}

/// Cycle focus through panes
fn update_focus_cycle(mut model: Model, direction: i32) -> Model {
    let pane_ids = model.pane_ids();
    if pane_ids.is_empty() {
        return model;
    }

    let current_idx = pane_ids
        .iter()
        .position(|&id| id == model.focused)
        .unwrap_or(0);
    let new_idx = if direction > 0 {
        (current_idx + 1) % pane_ids.len()
    } else {
        (current_idx + pane_ids.len() - 1) % pane_ids.len()
    };

    set_focus(&mut model, pane_ids[new_idx]);
    model
}

/// Focus pane in a direction (simplified - cycles for now)
fn update_focus_direction(mut model: Model, dir: Direction) -> Model {
    let focused = model.focused;
    let Some(&cur_rect) = model.pane_areas.get(&focused) else {
        return update_focus_cycle(model, 1);
    };

    // Center of the current pane
    let cur_cx = cur_rect.x as f64 + cur_rect.width as f64 / 2.0;
    let cur_cy = cur_rect.y as f64 + cur_rect.height as f64 / 2.0;

    // Find the best candidate in the requested direction.
    // "Best" = smallest distance whose center lies clearly in that direction.
    let mut best_id: Option<PaneId> = None;
    let mut best_dist = f64::MAX;

    for (&pane_id, &rect) in &model.pane_areas {
        if pane_id == focused { continue; }

        let px = rect.x as f64 + rect.width as f64 / 2.0;
        let py = rect.y as f64 + rect.height as f64 / 2.0;

        let dx = px - cur_cx;
        let dy = py - cur_cy;

        // The candidate must lie primarily in the requested direction.
        let qualifies = match dir {
            Direction::Left  => dx < 0.0 && dx.abs() >= dy.abs(),
            Direction::Right => dx > 0.0 && dx.abs() >= dy.abs(),
            Direction::Up    => dy < 0.0 && dy.abs() >= dx.abs(),
            Direction::Down  => dy > 0.0 && dy.abs() >= dx.abs(),
        };

        if qualifies {
            let dist = dx * dx + dy * dy;
            if dist < best_dist {
                best_dist = dist;
                best_id = Some(pane_id);
            }
        }
    }

    if let Some(id) = best_id {
        set_focus(&mut model, id);
    }
    model
}

/// Close a pane
fn update_close_pane(mut model: Model, pane_id: PaneId) -> Model {
    if model.panes.len() <= 1 {
        return model;
    }

    if let Some(pane_type) = model.get_pane(pane_id).map(|p| p.pane_type) {
        model = crate::hooks::on_pane_destroyed(model, pane_id, pane_type);
    }

    let mut split_to_remove: Option<SplitId> = None;
    let mut sibling_to_promote: Option<LayoutNode> = None;

    for split in &model.splits {
        match (&split.first, &split.second) {
            (LayoutNode::Pane(id), other) if *id == pane_id => {
                split_to_remove = Some(split.id);
                sibling_to_promote = Some(other.clone());
                break;
            }
            (other, LayoutNode::Pane(id)) if *id == pane_id => {
                split_to_remove = Some(split.id);
                sibling_to_promote = Some(other.clone());
                break;
            }
            _ => {}
        }
    }

    if let (Some(split_id), Some(sibling)) = (split_to_remove, sibling_to_promote) {
        if let LayoutNode::Split(root_split_id) = &model.root {
            if *root_split_id == split_id {
                model.root = sibling.clone();
            }
        }

        for split in &mut model.splits {
            if let LayoutNode::Split(id) = &split.first {
                if *id == split_id {
                    split.first = sibling.clone();
                }
            }
            if let LayoutNode::Split(id) = &split.second {
                if *id == split_id {
                    split.second = sibling.clone();
                }
            }
        }

        model.splits.retain(|s| s.id != split_id);
    }

    model.panes.retain(|p| p.id != pane_id);

    if model.focused == pane_id {
        if let Some(new_id) = model.panes.first().map(|p| p.id) {
            set_focus(&mut model, new_id);
        }
    }

    model
}

/// Resize a split
fn update_resize_split(mut model: Model, split_id: SplitId, delta: i16) -> Model {
    if let Some(split) = model.splits.iter_mut().find(|s| s.id == split_id) {
        let delta_ratio = delta as f64 / 100.0;
        split.ratio = (split.ratio + delta_ratio).clamp(0.1, 0.9);
    }
    model
}

/// Resize the focused split
fn update_resize_focused_split(mut model: Model, delta: i16, horizontal: bool) -> Model {
    let focused = model.focused;
    if let Some(split_id) = find_split_containing_pane(&model, focused) {
        if let Some(split) = model.splits.iter_mut().find(|s| s.id == split_id) {
            let matches = match split.orientation {
                Orientation::Horizontal => horizontal,
                Orientation::Vertical => !horizontal,
            };
            if matches {
                split.ratio = (split.ratio + delta as f64 / 100.0).clamp(0.1, 0.9);
            }
        }
    }
    model
}

/// Clear the selection indicator and deselect.
fn clear_selection(mut model: Model) -> Model {
    if let Some(sel_id) = model.selection_indicator_id.take() {
        for state in model.canvas_states.values_mut() {
            state.shapes.retain(|s| s.id != sel_id);
            state.animator.cancel_for_shape(sel_id);
        }
    }
    model.selected_node = None;
    model.detail_selection = common::tui::text::TextSelection::default();
    // Close any open task form and pop its shortcut contexts
    if model.task_edit.is_some() {
        model.task_edit = None;
        model.shortcut_stack.pop_above(crate::shortcuts::ContextName::DetailPane);
    }
    model
}

/// Select a node: record it globally and place an animated SelectionIndicator on the canvas.
fn set_selection(mut model: Model, pane_id: PaneId, shape_id: common::tui::canvas::ShapeId, cx: f64, cy: f64, w: f64, h: f64) -> Model {
    use std::time::Duration;
    use common::tui::canvas::{AnimValue, Animation, AnimationTarget, Easing, LayeredShape, SelectionIndicator, ShapeKind};

    model = clear_selection(model);
    model.selected_node = Some((pane_id, shape_id));

    let padding = 1.0;
    let base_w = w + padding * 2.0;
    let base_h = h + padding * 2.0;
    let indicator = SelectionIndicator::new(cx, cy, base_w, base_h, theme::RED);
    let mut sel_shape = LayeredShape::new(ShapeKind::SelectionIndicator(indicator), 1);
    sel_shape.entrance = None;
    let sel_id = sel_shape.id;

    if let Some(state) = model.canvas_states.get_mut(&pane_id) {
        state.shapes.push(sel_shape);

        let expand = 1.08;
        let duration = Duration::from_millis(800);

        let width_anim = Animation::new(
            AnimationTarget::ShapeWidth(sel_id),
            AnimValue::Float(base_w * expand),
            AnimValue::Float(base_w),
            duration,
        )
        .with_easing(Easing::EaseInOut)
        .ping_pong();
        state.animator.add(width_anim);

        let height_anim = Animation::new(
            AnimationTarget::ShapeHeight(sel_id),
            AnimValue::Float(base_h * expand),
            AnimValue::Float(base_h),
            duration,
        )
        .with_easing(Easing::EaseInOut)
        .ping_pong();
        state.animator.add(height_anim);

        let color_anim = Animation::new(
            AnimationTarget::ShapeColor(sel_id),
            AnimValue::Color(theme::RED),
            AnimValue::Color(theme::BG),
            duration,
        )
        .with_easing(Easing::EaseInOut)
        .ping_pong();
        state.animator.add(color_anim);
    }

    model.selection_indicator_id = Some(sel_id);
    model.detail_scroll = 0;
    model.detail_selection = common::tui::text::TextSelection::default();

    // Open task form if the selected shape is a Task node
    let pb_ref = model.canvas_states.get(&pane_id)
        .and_then(|s| s.shape_refs.get(&shape_id).cloned());
    if let Some(PlaybookRef::Task { set_id, index }) = pb_ref {
        model = open_task_form(model, set_id, index);
    }

    model
}

/// Build and open the task editor form for a given task.
fn open_task_form(mut model: Model, set_id: String, index: usize) -> Model {
    use common::tui::metadata::all_task_metadata;

    let task_json = model.playbook.as_ref()
        .and_then(|pb| pb.task_sets.get(&set_id))
        .and_then(|tasks| tasks.get(index))
        .and_then(|t| serde_json::to_value(t).ok());

    let Some(json) = task_json else { return model; };
    let op = json.get("op").and_then(|v| v.as_str()).unwrap_or("").to_string();

    let all = all_task_metadata();
    let meta = all.iter().find(|m| m.op == op.as_str());

    let fields: Vec<FieldEditState> = if let Some(meta) = meta {
        meta.fields.iter().map(|f| {
            let json_val = json.get(f.name);
            let value = match (f.type_hint, json_val) {
                ("bool", Some(v)) => FieldValue::Bool(v.as_bool().unwrap_or(false)),
                ("u8" | "u16" | "u32", Some(v)) => FieldValue::Int(
                    v.as_u64().map(|n| n.to_string()).unwrap_or_default()
                ),
                (_, Some(v)) if !v.is_null() => FieldValue::Text(match v {
                    serde_json::Value::String(s) => s.clone(),
                    other => other.to_string(),
                }),
                _ if f.required => match f.type_hint {
                    "bool" => FieldValue::Bool(false),
                    "u8" | "u16" | "u32" => FieldValue::Int(String::new()),
                    _ => FieldValue::Text(String::new()),
                },
                _ => FieldValue::Empty,
            };
            FieldEditState { name: f.name, type_hint: f.type_hint, required: f.required, value, editing: None }
        }).collect()
    } else {
        vec![]
    };

    model.task_edit = Some(TaskEditState { set_id, index, fields, selected: 0 });

    // If the detail pane is currently focused, push browse context
    if model.focused_pane_type() == Some(PaneType::Detail) {
        model.shortcut_stack.push(crate::shortcuts::detail_form_browse_context());
    }

    model
}

/// Remove all flowing connectors from every canvas state and re-add them from the
/// current playbook. Call this after any structural playbook edit (add/edit/delete node).
fn rebuild_cross_set_connectors(model: &mut Model) {
    use common::tui::canvas::{Connector, ShapeId};

    let playbook = match model.playbook.as_ref() {
        Some(pb) => pb,
        None => return,
    };

    const CROSS_SET_OPS: &[&str] = &[
        "migrate", "migrate_apc", "hollow", "hollow_apc",
        "create_thread", "sacrificial", "get_shellcode",
        "generate_exe", "generate_dll",
    ];

    let mut sorted_sets: Vec<(&String, &Vec<common::Task>)> = playbook.task_sets.iter().collect();
    sorted_sets.sort_by_key(|(k, _)| k.as_str());

    let canvas_pane_ids: Vec<PaneId> = model
        .panes
        .iter()
        .filter(|p| p.pane_type == PaneType::Canvas)
        .map(|p| p.id)
        .collect();

    for pane_id in canvas_pane_ids {
        let Some(state) = model.canvas_states.get_mut(&pane_id) else { continue };

        // Remove all previously flowing connectors (cross-set ones)
        state.connectors.retain(|c| c.flow.is_none());

        // Build set_name -> TaskSetLabel shape id map
        let mut set_label_ids: std::collections::HashMap<String, ShapeId> =
            std::collections::HashMap::new();
        for (shape_id, pb_ref) in &state.shape_refs {
            if let PlaybookRef::TaskSetLabel { set_id } = pb_ref {
                set_label_ids.insert(set_id.clone(), *shape_id);
            }
        }

        // Collect Task shapes
        let task_shapes: Vec<(ShapeId, String, usize)> = state
            .shape_refs
            .iter()
            .filter_map(|(id, pb_ref)| {
                if let PlaybookRef::Task { set_id, index } = pb_ref {
                    Some((*id, set_id.clone(), *index))
                } else {
                    None
                }
            })
            .collect();

        let playbook = model.playbook.as_ref().unwrap();
        let mut new_connectors: Vec<Connector> = Vec::new();
        for (shape_id, set_id, task_idx) in task_shapes {
            if let Some(tasks) = playbook.task_sets.get(&set_id) {
                if let Some(task) = tasks.get(task_idx) {
                    if let Ok(val) = serde_json::to_value(task) {
                        let op = val.get("op").and_then(|v| v.as_str()).unwrap_or("");
                        if CROSS_SET_OPS.contains(&op) {
                            let ref_idx = val
                                .get("task_id")
                                .or_else(|| val.get("task"))
                                .and_then(|v| v.as_u64());
                            if let Some(idx) = ref_idx {
                                if let Some((target_name, _)) = sorted_sets.get(idx as usize) {
                                    if let Some(&target_id) =
                                        set_label_ids.get(target_name.as_str())
                                    {
                                        new_connectors.push(
                                            Connector::new(shape_id, target_id)
                                                .with_color(theme::YELLOW)
                                                .with_flow(common::tui::canvas::Flow {
                                                    speed: 0.05,
                                                    gap: 0.07,
                                                    ..Default::default()
                                                })
                                        );
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        model.canvas_states.get_mut(&pane_id).unwrap().connectors.extend(new_connectors);
    }
}

/// Build canvas shapes and connectors from a loaded playbook.
/// Lays out each task_set as a horizontal row of connected nodes.
fn populate_canvas_from_playbook(model: &mut Model, playbook: &common::Playbook) {
    use common::tui::canvas::{Connector, Label, LabelPosition, LayeredShape, Node, ShapeKind};

    let h_gap = 4.0_f64; // horizontal gap between nodes
    let row_gap = 4.0_f64; // vertical gap between rows

    let row_colors = [
        theme::DARK_BLUE,
        theme::BLUE,
        theme::BRIGHT_CYAN,
        theme::CYAN,
    ];

    let mut sorted_sets: Vec<(&String, &Vec<common::Task>)> = playbook.task_sets.iter().collect();
    sorted_sets.sort_by_key(|(k, _)| k.as_str());

    let canvas_pane_ids: Vec<PaneId> = model
        .panes
        .iter()
        .filter(|p| p.pane_type == crate::model::PaneType::Canvas)
        .map(|p| p.id)
        .collect();

    for pane_id in canvas_pane_ids {
        let state = model
            .canvas_states
            .entry(pane_id)
            .or_insert_with(crate::model::CanvasState::new);

        state.shapes.clear();
        state.connectors.clear();
        state.shape_refs.clear();

        let mut row_bottom_y = 0.0_f64;
        let mut total_width = 0.0_f64;

        for (row_idx, (set_name, tasks)) in sorted_sets.iter().enumerate() {
            let row_color = row_colors[row_idx % row_colors.len()];

            // Pre-compute each task's (op, args, width, height)
            let task_specs: Vec<(String, Vec<(String, String)>, f64, f64)> = tasks
                .iter()
                .map(|t| {
                    let (op, args) = parse_task_info(t);
                    let (w, h) = node_dims(&op, &args);
                    (op, args, w, h)
                })
                .collect();

            // Name node dimensions
            let name_label = format!("task_{}", set_name);
            let name_w = (name_label.len() as f64 + 2.0).max(8.0);
            let name_h = 4.0_f64; // single text row: 1*2 + 2 padding

            // Row spacing = tallest node in the row (each node uses its own height)
            let row_h = task_specs
                .iter()
                .map(|(_, _, _, h)| *h)
                .fold(name_h, f64::max);

            // Name node
            let name_text = {
                use ratatui::style::{Modifier, Style};
                use ratatui::text::{Line, Span, Text};
                Text::from(Line::from(Span::styled(
                    name_label,
                    Style::default()
                        .fg(theme::BG)
                        //.bg(theme::BG)
                        .add_modifier(Modifier::BOLD),
                )))
            };
            let name_node = LayeredShape::new(
                ShapeKind::Node(Node::new(0.0, row_bottom_y, name_w, name_h).with_color(row_color)),
                2,
            )
            .with_label(Label::from_text(name_text, LabelPosition::Middle));
            let name_id = name_node.id;
            state.shape_refs.insert(name_id, PlaybookRef::TaskSetLabel { set_id: set_name.to_string() });
            let mut prev_id = name_id;
            state.shapes.push(name_node);

            let mut x_cursor = name_w + h_gap;

            // Task nodes — each sized to its own content
            for (task_idx, (op, args, node_w, node_h)) in task_specs.iter().enumerate() {
                let label_text = task_label_text(op, args);
                let shape = LayeredShape::new(
                    ShapeKind::Node(
                        Node::new(x_cursor, row_bottom_y, *node_w, *node_h).with_color(row_color),
                    ),
                    2,
                )
                .with_label(Label::from_text(label_text, LabelPosition::Middle));
                let id = shape.id;
                state.shape_refs.insert(id, PlaybookRef::Task { set_id: set_name.to_string(), index: task_idx });
                state.shapes.push(shape);
                state
                    .connectors
                    .push(Connector::static_line(prev_id, id, theme::FG));
                prev_id = id;
                x_cursor += node_w + h_gap;
            }

            // All task sets have a node that allows the creation of a new node at the end
            let add_text = {
                use ratatui::style::{Modifier, Style};
                use ratatui::text::{Line, Span, Text};
                Text::from(Line::from(Span::styled(
                    "+",
                    Style::default()
                        .fg(theme::BG)
                        //.bg(theme::FG)
                        .add_modifier(Modifier::BOLD),
                )))
            };

            let add_shape = LayeredShape::new(
                ShapeKind::Node(
                    Node::new(x_cursor, row_bottom_y, 4.0_f64, 4.0_f64).with_color(row_color),
                ),
                2,
            )
            .with_label(Label::from_text(add_text, LabelPosition::Middle));
            let id = add_shape.id;
            state.shape_refs.insert(id, PlaybookRef::AddButton { set_id: set_name.to_string() });
            state.shapes.push(add_shape);
            state
                .connectors
                .push(Connector::static_line(prev_id, id, theme::FG));

            total_width = total_width.max(x_cursor - h_gap);
            row_bottom_y -= row_h + row_gap;
        }

        // Center the view on all nodes
        if !sorted_sets.is_empty() {
            let total_height = (-row_bottom_y) - row_gap;
            state.canvas.center_x = total_width / 2.0;
            state.canvas.center_y = -total_height / 2.0;
        }
    }
}

/// Parse a task into (op_name, [(key, truncated_value)])
fn parse_task_info(task: &common::Task) -> (String, Vec<(String, String)>) {
    let Ok(val) = serde_json::to_value(task) else {
        return (format!("{task:?}"), vec![]);
    };
    let op = val
        .get("op")
        .and_then(|v| v.as_str())
        .unwrap_or("?")
        .to_string();
    let args = val
        .as_object()
        .map(|obj| {
            obj.iter()
                .filter(|(k, v)| k.as_str() != "op" && !v.is_null())
                .map(|(k, v)| {
                    let raw = match v {
                        serde_json::Value::String(s) => s.clone(),
                        other => other.to_string(),
                    };
                    let truncated: String = raw.chars().take(10).collect();
                    let display = if raw.chars().count() > 10 {
                        format!("{}…", truncated)
                    } else {
                        truncated
                    };
                    (k.clone(), display)
                })
                .collect()
        })
        .unwrap_or_default();
    (op, args)
}

/// Compute (canvas_width, canvas_height) for a node based on its content.
/// Assumes ~1 canvas unit per character horizontally, ~2 canvas units per row vertically.
fn node_dims(op: &str, args: &[(String, String)]) -> (f64, f64) {
    let n_rows = 1 + args.len();
    let max_chars = args
        .iter()
        .map(|(k, v)| k.len() + 1 + v.len())
        .fold(op.len(), usize::max);
    let w = (max_chars as f64 + 2.0).max(8.0);
    let h = (n_rows as f64 * 2.0 + 2.0).max(4.0);
    (w, h)
}

/// Build a multi-line styled Text for a task node label.
fn task_label_text(op: &str, args: &[(String, String)]) -> ratatui::text::Text<'static> {
    use ratatui::style::{Modifier, Style, Stylize};
    use ratatui::text::{Line, Span, Text};

    let mut lines = vec![Line::from(Span::styled(
        op.to_string(),
        Style::default()
            .fg(theme::YELLOW)
            .bg(theme::BG)
            .add_modifier(Modifier::BOLD),
    ))];
    for (k, v) in args {
        lines.push(Line::from(vec![
            Span::styled(k.clone(), Style::default().fg(theme::BG).add_modifier(Modifier::BOLD)),
            Span::styled(format!("={}", v), Style::default().fg(theme::BG)),
        ]));
    }
    Text::from(lines)
}

/// Helper: find split directly containing a pane
fn find_split_containing_pane(model: &Model, pane_id: PaneId) -> Option<SplitId> {
    for split in &model.splits {
        let in_first = matches!(&split.first, LayoutNode::Pane(id) if *id == pane_id);
        let in_second = matches!(&split.second, LayoutNode::Pane(id) if *id == pane_id);
        if in_first || in_second {
            return Some(split.id);
        }
    }
    None
}

// ─────────────────────────────────────────────────────────────────────────────
// ADD-NODE POPUP HANDLERS
// ─────────────────────────────────────────────────────────────────────────────

/// Resolve selected node → set_id + index, then open popup at index+offset (0=before, 1=after).
fn insert_relative_to_selected(model: Model, offset: usize) -> Model {
    let selected = model.selected_node;
    let resolved = selected.and_then(|(pane_id, shape_id)| {
        model.canvas_states.get(&pane_id).and_then(|state| {
            state.shape_refs.get(&shape_id).and_then(|r| match r {
                PlaybookRef::Task { set_id, index } => Some((set_id.clone(), index + offset)),
                PlaybookRef::AddButton { set_id } => {
                    // 'a' on AddButton = append; 'i' on AddButton = insert before last
                    let len = model.playbook.as_ref()
                        .and_then(|pb| pb.task_sets.get(set_id))
                        .map(|t| t.len())
                        .unwrap_or(0);
                    Some((set_id.clone(), if offset == 0 { len.saturating_sub(1) } else { len }))
                }
                _ => None,
            })
        })
    });
    if let Some((set_id, index)) = resolved {
        update(model, crate::message::Msg::OpenAddNodePopup { set_id, index })
    } else {
        model
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DELETE HANDLERS
// ─────────────────────────────────────────────────────────────────────────────

fn update_delete_selected(mut model: Model) -> Model {
    let Some((pane_id, shape_id)) = model.selected_node else { return model };
    let pb_ref = model
        .canvas_states
        .get(&pane_id)
        .and_then(|s| s.shape_refs.get(&shape_id))
        .cloned();
    match pb_ref {
        Some(PlaybookRef::Task { set_id, index }) => update_delete_node(model, set_id, index),
        Some(PlaybookRef::TaskSetLabel { set_id }) => {
            model.confirm_delete = Some(crate::model::ConfirmDeleteState { set_id, selected: 0 });
            model.shortcut_stack.push(crate::shortcuts::confirm_delete_popup_context());
            model
        }
        _ => model,
    }
}

fn update_delete_node(mut model: Model, set_id: String, index: usize) -> Model {
    // Remove from playbook
    if let Some(ref mut pb) = model.playbook {
        if let Some(tasks) = pb.task_sets.get_mut(&set_id) {
            if index < tasks.len() {
                tasks.remove(index);
            }
        }
    }

    let canvas_pane_ids: Vec<PaneId> = model
        .panes
        .iter()
        .filter(|p| p.pane_type == PaneType::Canvas)
        .map(|p| p.id)
        .collect();

    // Save selected_node before mutable loop to avoid borrow conflict
    let selected_node = model.selected_node;

    for pane_id in canvas_pane_ids {
        let Some(state) = model.canvas_states.get_mut(&pane_id) else { continue };

        let deleted_id = state
            .shape_refs
            .iter()
            .find(|(_, r)| matches!(r, PlaybookRef::Task { set_id: s, index: i } if s == &set_id && *i == index))
            .map(|(&sid, _)| sid);
        let Some(del_id) = deleted_id else { continue };

        // Relink: prev→deleted→next becomes prev→next
        let prev_id = state.connectors.iter()
            .find(|c| c.to == del_id && c.flow.is_none())
            .map(|c| c.from);
        let next_id = state.connectors.iter()
            .find(|c| c.from == del_id && c.flow.is_none())
            .map(|c| c.to);

        state.connectors.retain(|c| c.from != del_id && c.to != del_id);
        if let (Some(prev), Some(next)) = (prev_id, next_id) {
            state.connectors.push(
                common::tui::canvas::Connector::static_line(prev, next, theme::FG)
            );
        }

        state.shapes.retain(|s| s.id != del_id);
        state.shape_refs.remove(&del_id);

        // Shift down indices for later tasks in same set
        for pb_ref in state.shape_refs.values_mut() {
            if let PlaybookRef::Task { set_id: s, index: i } = pb_ref {
                if s == &set_id && *i > index {
                    *i -= 1;
                }
            }
        }

        // Clear selection if it was this node
        if selected_node == Some((pane_id, del_id)) {
            model.selected_node = None;
        }
    }

    let mut model = clear_selection(model);
    rebuild_cross_set_connectors(&mut model);
    crate::hooks::on_playbook_edited(model)
}

fn update_confirm_delete_task_set(mut model: Model) -> Model {
    let set_id = match model.confirm_delete.take() {
        Some(s) => s.set_id,
        None => return model,
    };
    model.shortcut_stack.pop_to(crate::shortcuts::ContextName::ConfirmDeletePopup);
    update_delete_task_set(model, set_id)
}

fn update_cancel_delete_task_set(mut model: Model) -> Model {
    model.confirm_delete = None;
    model.shortcut_stack.pop_to(crate::shortcuts::ContextName::ConfirmDeletePopup);
    model
}

fn update_confirm_delete_selected(model: Model) -> Model {
    let selected = model.confirm_delete.as_ref().map(|s| s.selected).unwrap_or(0);
    if selected == 0 {
        update_confirm_delete_task_set(model)
    } else {
        update_cancel_delete_task_set(model)
    }
}

fn update_add_task_set(mut model: Model) -> Model {
    use common::tui::canvas::{Connector, Label, LabelPosition, LayeredShape, Node, ShapeKind};

    let next_id = if let Some(ref pb) = model.playbook {
        let max = pb.task_sets.keys()
            .filter_map(|k| k.parse::<u64>().ok())
            .max()
            .unwrap_or(0);
        (max + 1).to_string()
    } else {
        return model;
    };

    if let Some(ref mut pb) = model.playbook {
        pb.task_sets.insert(next_id.clone(), Vec::new());
    }

    let h_gap = 4.0_f64;
    let row_gap = 4.0_f64;
    let row_h = 4.0_f64;
    let row_colors = [theme::DARK_BLUE, theme::BLUE, theme::BRIGHT_CYAN, theme::CYAN];

    // Determine which color index this set gets based on total set count
    let row_idx = model.playbook.as_ref()
        .map(|pb| pb.task_sets.len().saturating_sub(1))
        .unwrap_or(0);
    let row_color = row_colors[row_idx % row_colors.len()];

    let canvas_pane_ids: Vec<PaneId> = model.panes.iter()
        .filter(|p| p.pane_type == PaneType::Canvas)
        .map(|p| p.id)
        .collect();

    for pane_id in canvas_pane_ids {
        let state = match model.canvas_states.get_mut(&pane_id) {
            Some(s) => s,
            None => continue,
        };

        // Find the lowest Y among existing shapes (most negative = furthest down in canvas coords)
        let min_y = state.shapes.iter()
            .map(|s| {
                let (_, y) = s.shape.position();
                let (_, _, _, h) = s.shape.bounds();
                y - h
            })
            .fold(0.0_f64, f64::min);

        let row_y = min_y - row_gap - row_h;

        // Label node: "task_N"
        let name_label = format!("task_{}", next_id);
        let name_w = (name_label.len() as f64 + 2.0).max(8.0);
        let name_text = {
            use ratatui::style::{Modifier, Style};
            use ratatui::text::{Line, Span, Text};
            Text::from(Line::from(Span::styled(
                name_label,
                Style::default().fg(theme::BG).add_modifier(Modifier::BOLD),
            )))
        };
        let name_node = LayeredShape::new(
            ShapeKind::Node(Node::new(0.0, row_y, name_w, row_h).with_color(row_color)),
            2,
        )
        .with_label(Label::from_text(name_text, LabelPosition::Middle));
        let name_id = name_node.id;
        state.shape_refs.insert(name_id, PlaybookRef::TaskSetLabel { set_id: next_id.clone() });
        state.shapes.push(name_node);

        // Add button: "+"
        let add_x = name_w + h_gap;
        let add_text = {
            use ratatui::style::{Modifier, Style};
            use ratatui::text::{Line, Span, Text};
            Text::from(Line::from(Span::styled(
                "+",
                Style::default().fg(theme::BG).add_modifier(Modifier::BOLD),
            )))
        };
        let add_shape = LayeredShape::new(
            ShapeKind::Node(Node::new(add_x, row_y, 4.0, row_h).with_color(row_color)),
            2,
        )
        .with_label(Label::from_text(add_text, LabelPosition::Middle));
        let add_id = add_shape.id;
        state.shape_refs.insert(add_id, PlaybookRef::AddButton { set_id: next_id.clone() });
        state.shapes.push(add_shape);
        state.connectors.push(Connector::static_line(name_id, add_id, theme::FG));
    }

    crate::hooks::on_playbook_edited(model)
}

fn update_delete_task_set(mut model: Model, set_id: String) -> Model {
    // Remove from playbook
    if let Some(ref mut pb) = model.playbook {
        pb.task_sets.remove(&set_id);
    }

    let canvas_pane_ids: Vec<PaneId> = model
        .panes
        .iter()
        .filter(|p| p.pane_type == PaneType::Canvas)
        .map(|p| p.id)
        .collect();

    let selected_node = model.selected_node;

    for pane_id in canvas_pane_ids {
        let Some(state) = model.canvas_states.get_mut(&pane_id) else { continue };

        let set_shape_ids: Vec<common::tui::canvas::ShapeId> = state
            .shape_refs
            .iter()
            .filter(|(_, r)| match r {
                PlaybookRef::TaskSetLabel { set_id: s } => s == &set_id,
                PlaybookRef::Task { set_id: s, .. } => s == &set_id,
                PlaybookRef::AddButton { set_id: s } => s == &set_id,
            })
            .map(|(&sid, _)| sid)
            .collect();

        state.connectors.retain(|c| {
            !set_shape_ids.contains(&c.from) && !set_shape_ids.contains(&c.to)
        });
        state.shapes.retain(|s| !set_shape_ids.contains(&s.id));
        for sid in &set_shape_ids {
            state.shape_refs.remove(sid);
        }

        if let Some((pid, sid)) = selected_node {
            if pid == pane_id && set_shape_ids.contains(&sid) {
                model.selected_node = None;
            }
        }
    }

    let mut model = clear_selection(model);
    rebuild_cross_set_connectors(&mut model);
    crate::hooks::on_playbook_edited(model)
}

fn update_open_add_node_popup(mut model: Model, set_id: String, index: usize) -> Model {
    model.add_node_popup = Some(crate::model::AddNodePopupState {
        set_id,
        index,
        filter: String::new(),
        cursor: 0,
        selected: 0,
        scroll: 0,
    });
    model.shortcut_stack.push(crate::shortcuts::add_node_popup_context());
    model
}

fn update_add_node_popup_cancel(mut model: Model) -> Model {
    model.add_node_popup = None;
    model.shortcut_stack.pop_to(crate::shortcuts::ContextName::AddNodePopup);
    model
}

fn update_add_node_popup_char(mut model: Model, c: char) -> Model {
    if let Some(ref mut popup) = model.add_node_popup {
        popup.filter.push(c);
        popup.cursor = popup.filter.len();
        popup.selected = 0;
        popup.scroll = 0;
    }
    model
}

fn update_add_node_popup_backspace(mut model: Model) -> Model {
    if let Some(ref mut popup) = model.add_node_popup {
        popup.filter.pop();
        popup.cursor = popup.filter.len();
        popup.selected = 0;
        popup.scroll = 0;
    }
    model
}

fn update_add_node_popup_move(mut model: Model, delta: i32) -> Model {
    if let Some(ref mut popup) = model.add_node_popup {
        let all = common::tui::metadata::all_task_metadata();
        let count = common::tui::metadata::TaskMeta::filter(all, &popup.filter).len();
        if count == 0 { return model; }
        if delta < 0 {
            popup.selected = popup.selected.saturating_sub((-delta) as usize);
        } else {
            popup.selected = (popup.selected + delta as usize).min(count - 1);
        }
        // Scroll to keep selected in view (assume ~10 visible rows)
        let visible = 10usize;
        if popup.selected < popup.scroll {
            popup.scroll = popup.selected;
        } else if popup.selected >= popup.scroll + visible {
            popup.scroll = popup.selected + 1 - visible;
        }
    }
    model
}

fn update_add_node_popup_confirm(mut model: Model) -> Model {
    let action = model.add_node_popup.as_ref().and_then(|popup| {
        let all = common::tui::metadata::all_task_metadata();
        let filtered = common::tui::metadata::TaskMeta::filter(all, &popup.filter);
        filtered.get(popup.selected).map(|m| (popup.set_id.clone(), m.op.to_string(), popup.index))
    });

    model = update_add_node_popup_cancel(model);

    if let Some((set_id, op, index)) = action {
        model = update(model, crate::message::Msg::AddNode { set_id, op, index });
    }
    model
}

pub const GENERATE_OPTIONS: &[(&str, &str)] = &[
    ("Shellcode", "Raw shellcode + bytecode (.bin)"),
    ("EXE",       "PE executable (.exe)"),
    ("DLL",       "PE DLL (.dll)"),
];

fn update_generate_open(mut model: Model) -> Model {
    if model.playbook.is_none() {
        model.debug_state.error("No playbook loaded".to_string());
        return model;
    }
    model.generate_popup = Some(crate::model::GeneratePopupState { selected: 0 });
    model.shortcut_stack.push(crate::shortcuts::generate_popup_context());
    model
}

fn update_generate_cancel(mut model: Model) -> Model {
    model.generate_popup = None;
    model.shortcut_stack.pop_to(crate::shortcuts::ContextName::GeneratePopup);
    model
}

fn update_generate_move(mut model: Model, delta: i32) -> Model {
    if let Some(ref mut p) = model.generate_popup {
        let count = GENERATE_OPTIONS.len();
        if delta < 0 {
            p.selected = p.selected.saturating_sub((-delta) as usize);
        } else {
            p.selected = (p.selected + delta as usize).min(count - 1);
        }
    }
    model
}

fn update_generate_confirm(mut model: Model) -> Model {
    let selected = model.generate_popup.as_ref().map(|p| p.selected).unwrap_or(0);
    model = update_generate_cancel(model);

    // Serialize playbook to JSON value
    let pb = match model.playbook.as_ref() {
        Some(pb) => pb.clone(),
        None => return model,
    };
    let json_val = match serde_json::to_value(&pb) {
        Ok(v) => v,
        Err(e) => { model.debug_state.error(format!("Serialize failed: {e}")); return model; }
    };

    // Compile to bytecode
    let bytecode = match common::compiler::compile(&json_val) {
        Ok(b) => b,
        Err(e) => { model.debug_state.error(format!("Compile failed: {e}")); return model; }
    };

    // Derive output path from playbook path
    let base_path = model.playbook_path.as_deref().unwrap_or("playbook.json");
    let stem = std::path::Path::new(base_path)
        .with_extension("")
        .to_string_lossy()
        .to_string();

    let (ext, needs_shellcode) = match selected {
        0 => ("bin", true),
        1 => ("exe", true),
        _ => ("dll", true),
    };
    let out_path = format!("{stem}.{ext}");

    // Build payload
    let result = if needs_shellcode {
        crate::cli::find_base_shellcode(None).map(|sc| match selected {
            0 => crate::cli::generate_shellcode_payload(&sc, &bytecode),
            1 => crate::cli::generate_exe(&sc, &bytecode),
            _ => crate::cli::generate_dll(&sc, &bytecode),
        })
    } else {
        Ok(bytecode)
    };

    match result {
        Ok(payload) => {
            match std::fs::write(&out_path, &payload) {
                Ok(_) => {
                    let msg = format!("Generated {} ({} bytes)", out_path, payload.len());
                    model.debug_state.info(msg.clone());
                    model.toast = Some(crate::model::Toast::new(msg, std::time::Duration::from_secs(4)));
                }
                Err(e) => { model.debug_state.error(format!("Write failed: {e}")); }
            }
        }
        Err(e) => { model.debug_state.error(format!("Generate failed: {e}")); }
    }

    model
}

fn update_file_browser_open(mut model: Model) -> Model {
    model.file_browser = Some(crate::model::FileBrowserState::new());
    model.shortcut_stack.push(crate::shortcuts::file_browser_context());
    model
}

fn update_file_browser_cancel(mut model: Model) -> Model {
    model.file_browser = None;
    model.shortcut_stack.pop_to(crate::shortcuts::ContextName::FileBrowser);
    model
}

fn update_file_browser_move(mut model: Model, delta: i32) -> Model {
    if let Some(ref mut fb) = model.file_browser {
        fb.move_selection(delta);
    }
    model
}

fn update_file_browser_enter(mut model: Model) -> Model {
    let selected = model.file_browser.as_ref().and_then(|fb| fb.selected_path().cloned());
    if let Some(path) = selected {
        if path.is_dir() {
            if let Some(ref mut fb) = model.file_browser {
                fb.enter_dir();
            }
        } else {
            model = update_file_browser_cancel(model);
            let path_str = path.to_string_lossy().to_string();
            model = update(model, crate::message::Msg::Load { path: path_str });
        }
    }
    model
}

fn update_file_browser_up(mut model: Model) -> Model {
    if let Some(ref mut fb) = model.file_browser {
        fb.go_up();
    }
    model
}

fn update_new_playbook_open(mut model: Model) -> Model {
    let filename = "playbook.json".to_string();
    let cursor = filename.len();
    model.new_playbook_popup = Some(crate::model::NewPlaybookPopupState { filename, cursor, save_as: false });
    model.shortcut_stack.push(crate::shortcuts::new_playbook_popup_context());
    model
}

fn update_save_as_open(mut model: Model) -> Model {
    let filename = "playbook.json".to_string();
    let cursor = filename.len();
    model.new_playbook_popup = Some(crate::model::NewPlaybookPopupState { filename, cursor, save_as: true });
    model.shortcut_stack.push(crate::shortcuts::new_playbook_popup_context());
    model
}

fn update_new_playbook_cancel(mut model: Model) -> Model {
    model.new_playbook_popup = None;
    model.shortcut_stack.pop_to(crate::shortcuts::ContextName::NewPlaybookPopup);
    model
}

fn update_new_playbook_char(mut model: Model, c: char) -> Model {
    if let Some(ref mut popup) = model.new_playbook_popup {
        popup.filename.insert(popup.cursor, c);
        popup.cursor += c.len_utf8();
    }
    model
}

fn update_new_playbook_backspace(mut model: Model) -> Model {
    if let Some(ref mut popup) = model.new_playbook_popup {
        if popup.cursor > 0 {
            let prev = popup.filename[..popup.cursor]
                .char_indices()
                .last()
                .map(|(i, _)| i)
                .unwrap_or(0);
            popup.filename.remove(prev);
            popup.cursor = prev;
        }
    }
    model
}

fn update_new_playbook_confirm(mut model: Model) -> Model {
    let (filename, save_as) = match model.new_playbook_popup.as_ref() {
        Some(p) => (p.filename.trim().to_string(), p.save_as),
        None => return model,
    };
    if filename.is_empty() {
        return model;
    }
    model = update_new_playbook_cancel(model);

    if save_as {
        // Write the current in-memory playbook to the chosen path
        let json = match model.playbook.as_ref() {
            Some(pb) => match serde_json::to_string_pretty(pb) {
                Ok(j) => j,
                Err(e) => {
                    model.debug_state.error(format!("Failed to serialize playbook: {e}"));
                    return model;
                }
            },
            None => return model,
        };
        match std::fs::write(&filename, &json) {
            Ok(_) => {
                model.playbook_path = Some(filename.clone());
                model.debug_state.info(format!("Saved to {filename}"));
            }
            Err(e) => {
                model.debug_state.error(format!("Failed to save playbook: {e}"));
            }
        }
    } else {
        let blank = r#"{"task_sets":{"0":[]}}"#;
        match std::fs::write(&filename, blank) {
            Ok(_) => {
                model = update(model, crate::message::Msg::Load { path: filename });
            }
            Err(e) => {
                model.debug_state.error(format!("Failed to create playbook: {e}"));
            }
        }
    }
    model
}

fn update_add_node(mut model: Model, set_id: String, op: String, index: usize) -> Model {
    let all = common::tui::metadata::all_task_metadata();
    let meta = all.iter().find(|m| m.op == op.as_str());

    let json = if let Some(m) = meta { m.default_json() } else { serde_json::json!({ "op": op }) };

    let task = match serde_json::from_value::<common::Task>(json) {
        Ok(t) => t,
        Err(e) => {
            model.debug_state.error(format!("AddNode failed ({op}): {e}"));
            return model;
        }
    };

    // Insert into playbook at the given index
    if let Some(ref mut pb) = model.playbook {
        let tasks = pb.task_sets.entry(set_id.clone()).or_default();
        let clamped = index.min(tasks.len());
        tasks.insert(clamped, task);
    } else {
        return model;
    }

    let clamped_index = index.min(
        model.playbook.as_ref()
            .and_then(|pb| pb.task_sets.get(&set_id))
            .map(|t| t.len().saturating_sub(1))
            .unwrap_or(0)
    );

    // Parse display info for the new node
    let (task_op, task_args) = model.playbook.as_ref()
        .and_then(|pb| pb.task_sets.get(&set_id))
        .and_then(|tasks| tasks.get(clamped_index))
        .map(|t| parse_task_info(t))
        .unwrap_or_default();
    let (node_w, node_h) = node_dims(&task_op, &task_args);
    let h_gap = 4.0_f64;

    let canvas_pane_ids: Vec<PaneId> = model.panes.iter()
        .filter(|p| p.pane_type == PaneType::Canvas)
        .map(|p| p.id)
        .collect();

    for pane_id in canvas_pane_ids {
        use common::tui::canvas::{Connector, Label, LabelPosition, LayeredShape, Node, ShapeKind};

        // Collect shape info needed before mutable borrow
        // right_id = the shape currently at insertion index (Task at clamped_index) or AddButton
        // prev_id  = the shape just before insertion point
        let shape_info = model.canvas_states.get(&pane_id).map(|state| {
            // Find right_id: Task at clamped_index OR AddButton if appending
            let right_id = state.shape_refs.iter()
                .find(|(_, r)| matches!(r,
                    PlaybookRef::Task { set_id: s, index: i } if s == &set_id && *i == clamped_index
                        && !matches!(r, PlaybookRef::Task { index: ci, .. } if *ci < clamped_index)
                ))
                .map(|(&sid, _)| sid)
                .or_else(|| {
                    // Appending: use AddButton
                    state.shape_refs.iter()
                        .find(|(_, r)| matches!(r, PlaybookRef::AddButton { set_id: s } if s == &set_id))
                        .map(|(&sid, _)| sid)
                });

            // Find prev_id: Task at clamped_index - 1, or TaskSetLabel if inserting at 0
            let prev_id = if clamped_index == 0 {
                state.shape_refs.iter()
                    .find(|(_, r)| matches!(r, PlaybookRef::TaskSetLabel { set_id: s } if s == &set_id))
                    .map(|(&sid, _)| sid)
            } else {
                state.shape_refs.iter()
                    .find(|(_, r)| matches!(r,
                        PlaybookRef::Task { set_id: s, index: i } if s == &set_id && *i == clamped_index - 1
                    ))
                    .map(|(&sid, _)| sid)
            };

            // Insertion position = right_id's current position
            let insert_pos = right_id.and_then(|sid|
                state.shapes.iter().find(|s| s.id == sid).map(|s| s.shape.position())
            );

            // Row color from AddButton or any existing node in this set
            let add_btn_id = state.shape_refs.iter()
                .find(|(_, r)| matches!(r, PlaybookRef::AddButton { set_id: s } if s == &set_id))
                .map(|(&sid, _)| sid);
            let row_color = add_btn_id.and_then(|sid|
                state.shapes.iter().find(|s| s.id == sid)
                    .and_then(|sh| if let ShapeKind::Node(n) = &sh.shape { Some(n.color) } else { None })
            ).unwrap_or(theme::CYAN);

            // Collect all shapes to shift right (Task index >= clamped_index, plus AddButton)
            let to_shift: Vec<(common::tui::canvas::ShapeId, f64, f64)> = state.shape_refs.iter()
                .filter(|(_, r)| matches!(r,
                    PlaybookRef::Task { set_id: s, index: i } if s == &set_id && *i >= clamped_index
                ) || matches!(r, PlaybookRef::AddButton { set_id: s } if s == &set_id))
                .filter_map(|(&sid, _)| {
                    state.shapes.iter().find(|s| s.id == sid).map(|s| {
                        let (x, y) = s.shape.position();
                        (sid, x, y)
                    })
                })
                .collect();

            (right_id, prev_id, insert_pos, row_color, to_shift, add_btn_id)
        });

        let (right_id, prev_id, insert_pos, row_color, to_shift, add_btn_id) = match shape_info {
            Some(v) => v,
            None => continue,
        };

        let (ins_x, ins_y) = match insert_pos {
            Some(pos) => pos,
            None => continue,
        };

        // Shift all nodes at >= clamped_index right via MoveShape messages
        for (sid, x, y) in to_shift {
            model = update(model, crate::message::Msg::MoveShape {
                pane_id,
                shape_id: sid,
                x: x + node_w + h_gap,
                y,
            });
        }

        // Build new shape at insertion position
        let label_text = task_label_text(&task_op, &task_args);
        let new_shape = LayeredShape::new(
            ShapeKind::Node(Node::new(ins_x, ins_y, node_w, node_h).with_color(row_color)),
            2,
        )
        .with_label(Label::from_text(label_text, LabelPosition::Middle));
        let new_id = new_shape.id;

        if let Some(state) = model.canvas_states.get_mut(&pane_id) {
            // Increment shape_refs indices for all tasks >= clamped_index
            for r in state.shape_refs.values_mut() {
                if let PlaybookRef::Task { set_id: s, index: i } = r {
                    if s == &set_id && *i >= clamped_index {
                        *i += 1;
                    }
                }
            }

            // Rewire connectors: prev → right becomes prev → new → right
            if let (Some(prev), Some(right)) = (prev_id, right_id) {
                if let Some(conn) = state.connectors.iter_mut().find(|c| c.from == prev && c.to == right) {
                    conn.to = new_id;
                }
                state.connectors.push(Connector::static_line(new_id, right, theme::FG));
            } else if let Some(prev) = prev_id {
                // No right node (empty set, just name→add_btn) — redirect prev → new → add_btn
                if let Some(add_btn) = add_btn_id {
                    if let Some(conn) = state.connectors.iter_mut().find(|c| c.from == prev && c.to == add_btn) {
                        conn.to = new_id;
                    }
                    state.connectors.push(Connector::static_line(new_id, add_btn, theme::FG));
                }
            }

            state.shapes.push(new_shape);
            state.shape_refs.insert(new_id, PlaybookRef::Task {
                set_id: set_id.clone(),
                index: clamped_index,
            });
        }
    }

    let mut model = clear_selection(model);
    rebuild_cross_set_connectors(&mut model);
    crate::hooks::on_playbook_edited(model)
}

// ─────────────────────────────────────────────────────────────────────────────
// TASK FORM EDITOR HANDLERS
// ─────────────────────────────────────────────────────────────────────────────

fn form_field_move(mut model: Model, delta: i32) -> Model {
    if let Some(ref mut edit) = model.task_edit {
        let n = edit.fields.len();
        if n == 0 { return model; }
        if delta > 0 {
            edit.selected = (edit.selected + 1).min(n - 1);
        } else {
            edit.selected = edit.selected.saturating_sub(1);
        }
    }
    model
}

fn form_field_activate(mut model: Model) -> Model {
    let field_info = model.task_edit.as_ref().and_then(|e| {
        e.fields.get(e.selected).map(|f| (f.type_hint, f.value.clone()))
    });
    let Some((type_hint, value)) = field_info else { return model; };

    if type_hint == "bool" {
        // Toggle bool immediately — no edit mode needed
        if let Some(ref mut edit) = model.task_edit {
            if let Some(field) = edit.fields.get_mut(edit.selected) {
                field.value = match value {
                    FieldValue::Bool(b) => FieldValue::Bool(!b),
                    _ => FieldValue::Bool(true),
                };
            }
        }
        // Apply immediately
        model = apply_task_edit(model);
    } else {
        // Enter text/int editing mode
        let initial = value.display();
        if let Some(ref mut edit) = model.task_edit {
            if let Some(field) = edit.fields.get_mut(edit.selected) {
                field.editing = Some(FieldEditing::new(&initial));
            }
        }
        model.shortcut_stack.push(crate::shortcuts::detail_form_edit_context());
    }
    model
}

fn form_field_commit(mut model: Model) -> Model {
    // Pull buffer out before applying
    let commit_info = model.task_edit.as_ref().and_then(|e| {
        e.fields.get(e.selected).and_then(|f| {
            f.editing.as_ref().map(|ed| (f.type_hint, ed.buffer.clone(), f.required))
        })
    });
    let Some((type_hint, buffer, required)) = commit_info else { return model; };

    // Validate
    if type_hint == "u8" || type_hint == "u16" || type_hint == "u32" {
        if !buffer.is_empty() {
            if let Err(_) = buffer.parse::<u64>() {
                // Invalid number — don't commit, leave editing active
                return model;
            }
        } else if required {
            return model; // required int can't be empty
        }
    }

    // Apply validated value to field
    if let Some(ref mut edit) = model.task_edit {
        if let Some(field) = edit.fields.get_mut(edit.selected) {
            field.value = if buffer.is_empty() && !field.required {
                FieldValue::Empty
            } else {
                match type_hint {
                    "u8" | "u16" | "u32" => FieldValue::Int(buffer),
                    _ => FieldValue::Text(buffer),
                }
            };
            field.editing = None;
        }
    }

    // Pop edit context
    model.shortcut_stack.pop_to(crate::shortcuts::ContextName::DetailFormEdit);

    // Apply to playbook
    model = apply_task_edit(model);
    model
}

fn form_field_cancel(mut model: Model) -> Model {
    let is_editing = model.task_edit.as_ref()
        .and_then(|e| e.fields.get(e.selected))
        .map(|f| f.editing.is_some())
        .unwrap_or(false);

    if is_editing {
        // Cancel editing, stay in browse mode
        if let Some(ref mut edit) = model.task_edit {
            if let Some(field) = edit.fields.get_mut(edit.selected) {
                field.editing = None;
            }
        }
        model.shortcut_stack.pop_to(crate::shortcuts::ContextName::DetailFormEdit);
    } else {
        // Close the form entirely — but keep the canvas selection
        model.task_edit = None;
        model.shortcut_stack.pop_above(crate::shortcuts::ContextName::DetailPane);
    }
    model
}

fn form_field_clear(mut model: Model) -> Model {
    let can_clear = model.task_edit.as_ref()
        .and_then(|e| e.fields.get(e.selected))
        .map(|f| !f.required)
        .unwrap_or(false);

    if can_clear {
        if let Some(ref mut edit) = model.task_edit {
            if let Some(field) = edit.fields.get_mut(edit.selected) {
                field.value = FieldValue::Empty;
                field.editing = None;
            }
        }
        model = apply_task_edit(model);
    }
    model
}

/// Serialize the current form state and write it back to the playbook + canvas.
fn apply_task_edit(mut model: Model) -> Model {
    let edit_info = model.task_edit.as_ref().map(|e| (e.set_id.clone(), e.index, e.fields.clone()));
    let Some((set_id, index, fields)) = edit_info else { return model; };

    // Get current task JSON
    let current_json = model.playbook.as_ref()
        .and_then(|pb| pb.task_sets.get(&set_id))
        .and_then(|tasks| tasks.get(index))
        .and_then(|t| serde_json::to_value(t).ok());
    let Some(mut json) = current_json else { return model; };
    let Some(obj) = json.as_object_mut() else { return model; };

    // Patch each field
    for field in &fields {
        match &field.value {
            FieldValue::Empty => { obj.remove(field.name); }
            FieldValue::Bool(b) => { obj.insert(field.name.to_string(), serde_json::Value::Bool(*b)); }
            FieldValue::Int(s) => {
                if let Ok(n) = s.parse::<u64>() {
                    obj.insert(field.name.to_string(), serde_json::Value::Number(n.into()));
                }
            }
            FieldValue::Text(s) => {
                obj.insert(field.name.to_string(), serde_json::Value::String(s.clone()));
            }
        }
    }

    // Deserialize and write back
    match serde_json::from_value::<common::Task>(json) {
        Ok(new_task) => {
            if let Some(ref mut pb) = model.playbook {
                if let Some(tasks) = pb.task_sets.get_mut(&set_id) {
                    if let Some(slot) = tasks.get_mut(index) {
                        *slot = new_task;
                    }
                }
            }
            update_canvas_node_label(&mut model, &set_id, index);
            rebuild_cross_set_connectors(&mut model);
            model = crate::hooks::on_playbook_edited(model);
        }
        Err(e) => {
            model.debug_state.error(format!("Field edit failed: {e}"));
        }
    }
    model
}

/// Update the label of a canvas node after its task has been edited.
fn update_canvas_node_label(model: &mut Model, set_id: &str, task_index: usize) {
    let task_info = model.playbook.as_ref()
        .and_then(|pb| pb.task_sets.get(set_id))
        .and_then(|tasks| tasks.get(task_index))
        .map(parse_task_info);
    let Some((op, args)) = task_info else { return; };

    let canvas_panes: Vec<PaneId> = model.panes.iter()
        .filter(|p| p.pane_type == PaneType::Canvas)
        .map(|p| p.id)
        .collect();

    for pane_id in canvas_panes {
        if let Some(state) = model.canvas_states.get_mut(&pane_id) {
            let shape_id = state.shape_refs.iter()
                .find(|(_, r)| matches!(r, PlaybookRef::Task { set_id: s, index: i }
                    if s == set_id && *i == task_index))
                .map(|(&sid, _)| sid);
            if let Some(sid) = shape_id {
                if let Some(shape) = state.shapes.iter_mut().find(|s| s.id == sid) {
                    use common::tui::canvas::{Label, LabelPosition};
                    shape.label = Some(Label::from_text(task_label_text(&op, &args), LabelPosition::Middle));
                }
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SHORTCUT STACK MANAGEMENT
// ─────────────────────────────────────────────────────────────────────────────

/// Set focus to a pane and update shortcut stack accordingly
pub fn set_focus(model: &mut Model, pane_id: u32) {
    if !model.panes.iter().any(|p| p.id == pane_id) {
        return;
    }
    let old_type = model.focused_pane_type();
    model.focused = pane_id;
    let new_type = model.focused_pane_type();
    update_shortcuts_for_focus(model, old_type, new_type);
}

/// Update shortcut stack when focus changes
pub fn update_shortcuts_for_focus(
    model: &mut Model,
    old_pane_type: Option<PaneType>,
    new_pane_type: Option<PaneType>,
) {
    use crate::shortcuts::{self, ContextName};

    if old_pane_type == new_pane_type {
        return;
    }

    model.shortcut_stack.pop_above(ContextName::Global);

    if let Some(pane_type) = new_pane_type {
        for ctx in shortcuts::context_for_pane(pane_type) {
            model.shortcut_stack.push(ctx);
        }
        // If focusing the detail pane while a task form is open, also push the browse context
        if pane_type == PaneType::Detail && model.task_edit.is_some() {
            model.shortcut_stack.push(shortcuts::detail_form_browse_context());
        }
        // If focusing an agent pane that is still loading, restore the loading context
        if pane_type == PaneType::Agent {
            let loading = model.agent_states.get(&model.focused).map(|s| s.loading).unwrap_or(false);
            if loading {
                model.shortcut_stack.push(shortcuts::agent_loading_context());
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Setup wizard popup
// ─────────────────────────────────────────────────────────────────────────────

fn update_wizard_char(mut model: Model, c: char) -> Model {
    if let Some(ref mut popup) = model.wizard_popup {
        popup.input.insert(popup.cursor, c);
        popup.cursor += c.len_utf8();
    }
    model
}

fn update_wizard_backspace(mut model: Model) -> Model {
    if let Some(ref mut popup) = model.wizard_popup {
        if popup.cursor > 0 {
            let prev = popup.input[..popup.cursor]
                .char_indices()
                .last()
                .map(|(i, _)| i)
                .unwrap_or(0);
            popup.input.remove(prev);
            popup.cursor = prev;
        }
    }
    model
}

fn update_wizard_submit(mut model: Model) -> Model {
    let api_key = match model.wizard_popup.take() {
        Some(p) => p.input,
        None => return model,
    };
    crate::wizard::complete(model, api_key)
}

fn update_wizard_skip(mut model: Model) -> Model {
    model.wizard_popup = None;
    crate::wizard::complete(model, String::new())
}
