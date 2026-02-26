//! Keyboard shortcut system with stack-based context management.

use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use crate::message::Msg;

// ═══════════════════════════════════════════════════════════════════════════════
// KEY COMBO
// ═══════════════════════════════════════════════════════════════════════════════

/// A key combination (code + modifiers)
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct KeyCombo {
    pub code: KeyCode,
    pub modifiers: KeyModifiers,
}

impl KeyCombo {
    pub fn new(code: KeyCode, modifiers: KeyModifiers) -> Self {
        Self { code, modifiers }
    }

    pub fn plain(code: KeyCode) -> Self {
        Self::new(code, KeyModifiers::NONE)
    }

    pub fn ctrl(c: char) -> Self {
        Self::new(KeyCode::Char(c), KeyModifiers::CONTROL)
    }

    pub fn shift(code: KeyCode) -> Self {
        Self::new(code, KeyModifiers::SHIFT)
    }

    pub fn alt(code: KeyCode) -> Self {
        Self::new(code, KeyModifiers::ALT)
    }

    pub fn matches(&self, key: &KeyEvent) -> bool {
        if self.code != key.code {
            return false;
        }
        if self.modifiers.is_empty() {
            let dominated = key.modifiers - KeyModifiers::SHIFT;
            return dominated.is_empty();
        }
        key.modifiers.contains(self.modifiers)
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// SHORTCUT ACTION
// ═══════════════════════════════════════════════════════════════════════════════

#[derive(Clone)]
pub enum ShortcutAction {
    Static(fn() -> Msg),
    Dynamic(fn(KeyEvent) -> Msg),
}

impl std::fmt::Debug for ShortcutAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Static(_) => write!(f, "Static(...)"),
            Self::Dynamic(_) => write!(f, "Dynamic(...)"),
        }
    }
}

impl ShortcutAction {
    pub fn to_msg(&self, key: KeyEvent) -> Msg {
        match self {
            Self::Static(f) => f(),
            Self::Dynamic(f) => f(key),
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// SHORTCUT
// ═══════════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone)]
pub struct Shortcut {
    pub combo: KeyCombo,
    pub action: ShortcutAction,
    pub description: &'static str,
}

impl Shortcut {
    pub fn new(combo: KeyCombo, action: ShortcutAction, description: &'static str) -> Self {
        Self { combo, action, description }
    }

    pub fn static_msg(combo: KeyCombo, msg_fn: fn() -> Msg, description: &'static str) -> Self {
        Self::new(combo, ShortcutAction::Static(msg_fn), description)
    }

    pub fn dynamic(combo: KeyCombo, msg_fn: fn(KeyEvent) -> Msg, description: &'static str) -> Self {
        Self::new(combo, ShortcutAction::Dynamic(msg_fn), description)
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// SHORTCUT CONTEXT
// ═══════════════════════════════════════════════════════════════════════════════

/// Name of a shortcut context (for matching when popping)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ContextName {
    Global,
    PaneCommand,
    TextInput,
    AgentPane,
    CanvasPane,
    DetailPane,
    DetailFormBrowse,
    DetailFormEdit,
    AddNodePopup,
    ConfirmDeletePopup,
    GeneratePopup,
    NewPlaybookPopup,
    FileBrowser,
    WizardPopup,
    AgentLoading,
}

/// A named context containing shortcuts
#[derive(Debug, Clone)]
pub struct ShortcutContext {
    pub name: ContextName,
    pub shortcuts: Vec<Shortcut>,
    pub char_handler: Option<fn(char) -> Msg>,
    pub passthrough_unhandled: bool,
}

impl ShortcutContext {
    pub fn new(name: ContextName) -> Self {
        Self {
            name,
            shortcuts: Vec::new(),
            char_handler: None,
            passthrough_unhandled: true,
        }
    }

    pub fn passthrough(mut self, passthrough: bool) -> Self {
        self.passthrough_unhandled = passthrough;
        self
    }

    pub fn with_char_handler(mut self, handler: fn(char) -> Msg) -> Self {
        self.char_handler = Some(handler);
        self
    }

    pub fn add(mut self, shortcut: Shortcut) -> Self {
        self.shortcuts.push(shortcut);
        self
    }

    pub fn find(&self, key: &KeyEvent) -> Option<&Shortcut> {
        self.shortcuts.iter().find(|s| s.combo.matches(key))
    }

    pub fn handles_char(&self, key: &KeyEvent) -> Option<Msg> {
        if let KeyCode::Char(c) = key.code {
            if key.modifiers.is_empty() || key.modifiers == KeyModifiers::SHIFT {
                if let Some(handler) = self.char_handler {
                    return Some(handler(c));
                }
            }
        }
        None
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// SHORTCUT STACK
// ═══════════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone)]
pub struct ShortcutStack {
    contexts: Vec<ShortcutContext>,
}

impl Default for ShortcutStack {
    fn default() -> Self {
        Self::new()
    }
}

impl ShortcutStack {
    pub fn new() -> Self {
        Self { contexts: Vec::new() }
    }

    pub fn push(&mut self, context: ShortcutContext) {
        self.contexts.push(context);
    }

    pub fn pop(&mut self) -> Option<ShortcutContext> {
        self.contexts.pop()
    }

    /// Pop contexts until we find one with the given name (inclusive)
    pub fn pop_to(&mut self, name: ContextName) {
        if !self.contexts.iter().any(|c| c.name == name) {
            return;
        }
        while let Some(ctx) = self.contexts.last() {
            let found = ctx.name == name;
            self.contexts.pop();
            if found {
                return;
            }
        }
    }

    /// Pop all contexts above the given name (keeps the named context)
    pub fn pop_above(&mut self, name: ContextName) {
        if let Some(pos) = self.contexts.iter().position(|c| c.name == name) {
            self.contexts.truncate(pos + 1);
        }
    }

    /// Check if a context with the given name is on the stack
    pub fn has(&self, name: ContextName) -> bool {
        self.contexts.iter().any(|c| c.name == name)
    }

    /// Get the name of the top context
    pub fn top_name(&self) -> Option<ContextName> {
        self.contexts.last().map(|c| c.name)
    }

    /// Find the action for a key, searching from top to bottom
    pub fn find_action(&self, key: &KeyEvent) -> Option<Msg> {
        for ctx in self.contexts.iter().rev() {
            if let Some(shortcut) = ctx.find(key) {
                return Some(shortcut.action.to_msg(key.clone()));
            }
            if let Some(msg) = ctx.handles_char(key) {
                return Some(msg);
            }
            if !ctx.passthrough_unhandled {
                return None;
            }
        }
        None
    }

    pub fn debug_stack(&self) -> Vec<ContextName> {
        self.contexts.iter().map(|c| c.name).collect()
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// PREDEFINED CONTEXTS
// ═══════════════════════════════════════════════════════════════════════════════

/// Global shortcuts (always at bottom of stack)
pub fn global_context() -> ShortcutContext {
    ShortcutContext::new(ContextName::Global)
        .add(Shortcut::static_msg(
            KeyCombo::ctrl('w'),
            || Msg::EnterPaneCommand,
            "Enter pane command mode",
        ))
        .add(Shortcut::static_msg(
            KeyCombo::ctrl('c'),
            || Msg::CtrlCPressed,
            "Clear input or quit",
        ))
}

/// Pane command mode (after Ctrl+W)
pub fn pane_command_context() -> ShortcutContext {
    ShortcutContext::new(ContextName::PaneCommand)
        .passthrough(false)
        .add(Shortcut::static_msg(
            KeyCombo::plain(KeyCode::Char('h')),
            || Msg::FocusDirection(crate::message::Direction::Left),
            "Focus left",
        ))
        .add(Shortcut::static_msg(
            KeyCombo::plain(KeyCode::Left),
            || Msg::FocusDirection(crate::message::Direction::Left),
            "Focus left",
        ))
        .add(Shortcut::static_msg(
            KeyCombo::plain(KeyCode::Char('j')),
            || Msg::FocusDirection(crate::message::Direction::Down),
            "Focus down",
        ))
        .add(Shortcut::static_msg(
            KeyCombo::plain(KeyCode::Down),
            || Msg::FocusDirection(crate::message::Direction::Down),
            "Focus down",
        ))
        .add(Shortcut::static_msg(
            KeyCombo::plain(KeyCode::Char('k')),
            || Msg::FocusDirection(crate::message::Direction::Up),
            "Focus up",
        ))
        .add(Shortcut::static_msg(
            KeyCombo::plain(KeyCode::Up),
            || Msg::FocusDirection(crate::message::Direction::Up),
            "Focus up",
        ))
        .add(Shortcut::static_msg(
            KeyCombo::plain(KeyCode::Char('l')),
            || Msg::FocusDirection(crate::message::Direction::Right),
            "Focus right",
        ))
        .add(Shortcut::static_msg(
            KeyCombo::plain(KeyCode::Right),
            || Msg::FocusDirection(crate::message::Direction::Right),
            "Focus right",
        ))
        .add(Shortcut::static_msg(
            KeyCombo::plain(KeyCode::Char('w')),
            || Msg::FocusNext,
            "Cycle focus",
        ))
        .add(Shortcut::static_msg(
            KeyCombo::plain(KeyCode::Char('v')),
            || Msg::Split(crate::message::Orientation::Vertical),
            "Vertical split",
        ))
        .add(Shortcut::static_msg(
            KeyCombo::plain(KeyCode::Char('s')),
            || Msg::Split(crate::message::Orientation::Horizontal),
            "Horizontal split",
        ))
        .add(Shortcut::static_msg(
            KeyCombo::plain(KeyCode::Char('+')),
            || Msg::ResizeSplit { delta: 2 },
            "Increase split size",
        ))
        .add(Shortcut::static_msg(
            KeyCombo::plain(KeyCode::Char('=')),
            || Msg::ResizeSplit { delta: 2 },
            "Increase split size",
        ))
        .add(Shortcut::static_msg(
            KeyCombo::plain(KeyCode::Char('-')),
            || Msg::ResizeSplit { delta: -2 },
            "Decrease split size",
        ))
        .add(Shortcut::static_msg(
            KeyCombo::plain(KeyCode::Char('>')),
            || Msg::ResizeSplitHorizontal { delta: 2 },
            "Increase horizontal split size",
        ))
        .add(Shortcut::static_msg(
            KeyCombo::plain(KeyCode::Char('<')),
            || Msg::ResizeSplitHorizontal { delta: -2 },
            "Decrease horizontal split size",
        ))
        .add(Shortcut::static_msg(
            KeyCombo::plain(KeyCode::Char('q')),
            || Msg::ClosePane,
            "Close pane",
        ))
        .add(Shortcut::static_msg(
            KeyCombo::plain(KeyCode::Char('c')),
            || Msg::ClosePane,
            "Close pane",
        ))
        .add(Shortcut::static_msg(
            KeyCombo::plain(KeyCode::Esc),
            || Msg::ExitPaneCommand,
            "Exit pane command mode",
        ))
}

/// Shared text input shortcuts (cursor movement, editing)
pub fn text_input_context() -> ShortcutContext {
    ShortcutContext::new(ContextName::TextInput)
        .with_char_handler(|c| Msg::InsertChar(c))
        .add(Shortcut::static_msg(
            KeyCombo::ctrl('a'),
            || Msg::CursorHome,
            "Beginning of line",
        ))
        .add(Shortcut::static_msg(
            KeyCombo::ctrl('e'),
            || Msg::CursorEnd,
            "End of line",
        ))
        .add(Shortcut::static_msg(
            KeyCombo::ctrl('u'),
            || Msg::ClearLine,
            "Clear line",
        ))
        .add(Shortcut::static_msg(
            KeyCombo::plain(KeyCode::Backspace),
            || Msg::DeleteBack,
            "Delete backward",
        ))
        .add(Shortcut::static_msg(
            KeyCombo::plain(KeyCode::Left),
            || Msg::CursorLeft,
            "Move cursor left",
        ))
        .add(Shortcut::static_msg(
            KeyCombo::plain(KeyCode::Right),
            || Msg::CursorRight,
            "Move cursor right",
        ))
        .add(Shortcut::static_msg(
            KeyCombo::plain(KeyCode::Home),
            || Msg::CursorHome,
            "Move cursor to start",
        ))
        .add(Shortcut::static_msg(
            KeyCombo::plain(KeyCode::End),
            || Msg::CursorEnd,
            "Move cursor to end",
        ))
}

/// Agent pane shortcuts
pub fn agent_pane_context() -> ShortcutContext {
    ShortcutContext::new(ContextName::AgentPane)
        .add(Shortcut::static_msg(
            KeyCombo::plain(KeyCode::Enter),
            || Msg::AgentSubmitInput,
            "Submit message",
        ))
        .add(Shortcut::static_msg(
            KeyCombo::plain(KeyCode::Up),
            || Msg::ScrollUp(1),
            "Scroll up",
        ))
        .add(Shortcut::static_msg(
            KeyCombo::plain(KeyCode::Down),
            || Msg::ScrollDown(1),
            "Scroll down",
        ))
        .add(Shortcut::static_msg(
            KeyCombo::plain(KeyCode::PageUp),
            || Msg::ScrollPageUp,
            "Page up",
        ))
        .add(Shortcut::static_msg(
            KeyCombo::plain(KeyCode::PageDown),
            || Msg::ScrollPageDown,
            "Page down",
        ))
}

/// Canvas pane shortcuts
pub fn canvas_pane_context() -> ShortcutContext {
    ShortcutContext::new(ContextName::CanvasPane)
        .add(Shortcut::static_msg(
            KeyCombo::plain(KeyCode::Char('h')),
            || Msg::CanvasPan { dx: 5.0, dy: 0.0 },
            "Pan left",
        ))
        .add(Shortcut::static_msg(
            KeyCombo::plain(KeyCode::Left),
            || Msg::CanvasPan { dx: 5.0, dy: 0.0 },
            "Pan left",
        ))
        .add(Shortcut::static_msg(
            KeyCombo::plain(KeyCode::Char('j')),
            || Msg::CanvasPan { dx: 0.0, dy: -5.0 },
            "Pan down",
        ))
        .add(Shortcut::static_msg(
            KeyCombo::plain(KeyCode::Down),
            || Msg::CanvasPan { dx: 0.0, dy: -5.0 },
            "Pan down",
        ))
        .add(Shortcut::static_msg(
            KeyCombo::plain(KeyCode::Char('k')),
            || Msg::CanvasPan { dx: 0.0, dy: 5.0 },
            "Pan up",
        ))
        .add(Shortcut::static_msg(
            KeyCombo::plain(KeyCode::Up),
            || Msg::CanvasPan { dx: 0.0, dy: 5.0 },
            "Pan up",
        ))
        .add(Shortcut::static_msg(
            KeyCombo::plain(KeyCode::Char('l')),
            || Msg::CanvasPan { dx: -5.0, dy: 0.0 },
            "Pan right",
        ))
        .add(Shortcut::static_msg(
            KeyCombo::plain(KeyCode::Right),
            || Msg::CanvasPan { dx: -5.0, dy: 0.0 },
            "Pan right",
        ))
        .add(Shortcut::static_msg(
            KeyCombo::plain(KeyCode::Char('+')),
            || Msg::CanvasZoom { delta: 0.1 },
            "Zoom in",
        ))
        .add(Shortcut::static_msg(
            KeyCombo::plain(KeyCode::Char('=')),
            || Msg::CanvasZoom { delta: 0.1 },
            "Zoom in",
        ))
        .add(Shortcut::static_msg(
            KeyCombo::plain(KeyCode::Char('-')),
            || Msg::CanvasZoom { delta: -0.1 },
            "Zoom out",
        ))
        .add(Shortcut::static_msg(
            KeyCombo::plain(KeyCode::Char('r')),
            || Msg::CanvasResetView,
            "Reset view",
        ))
        .add(Shortcut::static_msg(
            KeyCombo::plain(KeyCode::Char('a')),
            || Msg::InsertAfterSelected,
            "Insert node after selected",
        ))
        .add(Shortcut::static_msg(
            KeyCombo::plain(KeyCode::Char('i')),
            || Msg::InsertBeforeSelected,
            "Insert node before selected",
        ))
        .add(Shortcut::static_msg(
            KeyCombo::plain(KeyCode::Delete),
            || Msg::DeleteSelected,
            "Delete selected node / task set",
        ))
        .add(Shortcut::static_msg(
            KeyCombo::plain(KeyCode::Char('t')),
            || Msg::AddTaskSet,
            "Add task set",
        ))
        .add(Shortcut::static_msg(
            KeyCombo::plain(KeyCode::Char('n')),
            || Msg::NewPlaybook,
            "New playbook",
        ))
        .add(Shortcut::static_msg(
            KeyCombo::plain(KeyCode::Char('o')),
            || Msg::OpenFileBrowser,
            "Open playbook",
        ))
        .add(Shortcut::static_msg(
            KeyCombo::plain(KeyCode::Char('g')),
            || Msg::Generate,
            "Generate payload",
        ))
}

/// Generate-payload popup (j/k or arrows to select format, Enter to generate, Esc to cancel)
pub fn generate_popup_context() -> ShortcutContext {
    ShortcutContext::new(ContextName::GeneratePopup)
        .passthrough(false)
        .add(Shortcut::static_msg(KeyCombo::plain(KeyCode::Char('j')), || Msg::GeneratePopupMove(1),  "Down"))
        .add(Shortcut::static_msg(KeyCombo::plain(KeyCode::Down),      || Msg::GeneratePopupMove(1),  "Down"))
        .add(Shortcut::static_msg(KeyCombo::plain(KeyCode::Char('k')), || Msg::GeneratePopupMove(-1), "Up"))
        .add(Shortcut::static_msg(KeyCombo::plain(KeyCode::Up),        || Msg::GeneratePopupMove(-1), "Up"))
        .add(Shortcut::static_msg(KeyCombo::plain(KeyCode::Enter),     || Msg::GeneratePopupConfirm,  "Generate"))
        .add(Shortcut::static_msg(KeyCombo::plain(KeyCode::Esc),       || Msg::GeneratePopupCancel,   "Cancel"))
}

/// File browser popup (j/k or arrows to navigate, Enter to enter dir or open file, h/Backspace to go up, Esc to cancel)
pub fn file_browser_context() -> ShortcutContext {
    ShortcutContext::new(ContextName::FileBrowser)
        .passthrough(false)
        .add(Shortcut::static_msg(KeyCombo::plain(KeyCode::Char('j')), || Msg::FileBrowserMove(1), "Down"))
        .add(Shortcut::static_msg(KeyCombo::plain(KeyCode::Down),      || Msg::FileBrowserMove(1), "Down"))
        .add(Shortcut::static_msg(KeyCombo::plain(KeyCode::Char('k')), || Msg::FileBrowserMove(-1), "Up"))
        .add(Shortcut::static_msg(KeyCombo::plain(KeyCode::Up),        || Msg::FileBrowserMove(-1), "Up"))
        .add(Shortcut::static_msg(KeyCombo::plain(KeyCode::Enter),     || Msg::FileBrowserEnter, "Open / enter dir"))
        .add(Shortcut::static_msg(KeyCombo::plain(KeyCode::Char('l')), || Msg::FileBrowserEnter, "Open / enter dir"))
        .add(Shortcut::static_msg(KeyCombo::plain(KeyCode::Right),     || Msg::FileBrowserEnter, "Open / enter dir"))
        .add(Shortcut::static_msg(KeyCombo::plain(KeyCode::Char('h')), || Msg::FileBrowserUp, "Parent directory"))
        .add(Shortcut::static_msg(KeyCombo::plain(KeyCode::Backspace), || Msg::FileBrowserUp, "Parent directory"))
        .add(Shortcut::static_msg(KeyCombo::plain(KeyCode::Left),      || Msg::FileBrowserUp, "Parent directory"))
        .add(Shortcut::static_msg(KeyCombo::plain(KeyCode::Esc),       || Msg::FileBrowserCancel, "Cancel"))
}

/// Agent loading state — Esc cancels the in-progress request
pub fn agent_loading_context() -> ShortcutContext {
    ShortcutContext::new(ContextName::AgentLoading)
        .passthrough(false)
        .add(Shortcut::static_msg(KeyCombo::plain(KeyCode::Esc), || Msg::AgentCancel, "Cancel agent request"))
}

/// First-run setup wizard API key input
pub fn wizard_popup_context() -> ShortcutContext {
    ShortcutContext::new(ContextName::WizardPopup)
        .passthrough(false)
        .with_char_handler(|c| Msg::WizardChar(c))
        .add(Shortcut::static_msg(KeyCombo::plain(KeyCode::Backspace), || Msg::WizardBackspace, "Delete character"))
        .add(Shortcut::static_msg(KeyCombo::plain(KeyCode::Enter), || Msg::WizardSubmit, "Save and continue"))
        .add(Shortcut::static_msg(KeyCombo::plain(KeyCode::Esc), || Msg::WizardSkip, "Skip"))
        .add(Shortcut::static_msg(KeyCombo::plain(KeyCode::Up), || Msg::WizardUp, "Move up"))
        .add(Shortcut::static_msg(KeyCombo::plain(KeyCode::Down), || Msg::WizardDown, "Move down"))
}

/// New-playbook filename popup
pub fn new_playbook_popup_context() -> ShortcutContext {
    ShortcutContext::new(ContextName::NewPlaybookPopup)
        .passthrough(false)
        .with_char_handler(|c| Msg::NewPlaybookPopupChar(c))
        .add(Shortcut::static_msg(KeyCombo::plain(KeyCode::Backspace), || Msg::NewPlaybookPopupBackspace, "Delete character"))
        .add(Shortcut::static_msg(KeyCombo::plain(KeyCode::Enter), || Msg::NewPlaybookPopupConfirm, "Create"))
        .add(Shortcut::static_msg(KeyCombo::plain(KeyCode::Esc), || Msg::NewPlaybookPopupCancel, "Cancel"))
}

/// Confirm-delete task set popup (y=yes, n/c=cancel, arrows/tab=navigate, enter=confirm selected)
pub fn confirm_delete_popup_context() -> ShortcutContext {
    ShortcutContext::new(ContextName::ConfirmDeletePopup)
        .passthrough(false)
        // Direct hotkeys
        .add(Shortcut::static_msg(KeyCombo::plain(KeyCode::Char('y')), || Msg::ConfirmDeleteTaskSet, "Yes"))
        .add(Shortcut::static_msg(KeyCombo::plain(KeyCode::Char('Y')), || Msg::ConfirmDeleteTaskSet, "Yes"))
        .add(Shortcut::static_msg(KeyCombo::shift(KeyCode::Char('Y')), || Msg::ConfirmDeleteTaskSet, "Yes"))
        .add(Shortcut::static_msg(KeyCombo::plain(KeyCode::Char('n')), || Msg::CancelDeleteTaskSet, "Cancel"))
        .add(Shortcut::static_msg(KeyCombo::plain(KeyCode::Char('N')), || Msg::CancelDeleteTaskSet, "Cancel"))
        .add(Shortcut::static_msg(KeyCombo::shift(KeyCode::Char('N')), || Msg::CancelDeleteTaskSet, "Cancel"))
        .add(Shortcut::static_msg(KeyCombo::plain(KeyCode::Char('c')), || Msg::CancelDeleteTaskSet, "Cancel"))
        .add(Shortcut::static_msg(KeyCombo::plain(KeyCode::Char('C')), || Msg::CancelDeleteTaskSet, "Cancel"))
        .add(Shortcut::static_msg(KeyCombo::shift(KeyCode::Char('C')), || Msg::CancelDeleteTaskSet, "Cancel"))
        // Esc always cancels
        .add(Shortcut::static_msg(KeyCombo::plain(KeyCode::Esc), || Msg::CancelDeleteTaskSet, "Cancel"))
        // Enter confirms highlighted option
        .add(Shortcut::static_msg(KeyCombo::plain(KeyCode::Enter), || Msg::ConfirmDeleteSelected, "Confirm selected"))
        // Navigation
        .add(Shortcut::static_msg(KeyCombo::plain(KeyCode::Left), || Msg::ConfirmDeleteSelectPrev, "Previous option"))
        .add(Shortcut::static_msg(KeyCombo::plain(KeyCode::Right), || Msg::ConfirmDeleteSelectNext, "Next option"))
        .add(Shortcut::static_msg(KeyCombo::plain(KeyCode::Tab), || Msg::ConfirmDeleteSelectNext, "Next option"))
}

/// Add-node popup shortcuts (captures all keys, no passthrough)
pub fn add_node_popup_context() -> ShortcutContext {
    ShortcutContext::new(ContextName::AddNodePopup)
        .passthrough(false)
        .with_char_handler(|c| Msg::AddNodePopupChar(c))
        .add(Shortcut::static_msg(
            KeyCombo::plain(KeyCode::Backspace),
            || Msg::AddNodePopupBackspace,
            "Delete filter character",
        ))
        .add(Shortcut::static_msg(
            KeyCombo::plain(KeyCode::Up),
            || Msg::AddNodePopupMove(-1),
            "Move selection up",
        ))
        .add(Shortcut::static_msg(
            KeyCombo::plain(KeyCode::Down),
            || Msg::AddNodePopupMove(1),
            "Move selection down",
        ))
        .add(Shortcut::static_msg(
            KeyCombo::plain(KeyCode::Enter),
            || Msg::AddNodePopupConfirm,
            "Confirm selection",
        ))
        .add(Shortcut::static_msg(
            KeyCombo::plain(KeyCode::Esc),
            || Msg::AddNodePopupCancel,
            "Cancel popup",
        ))
}

/// Detail form browse mode: navigate fields, activate, cancel
pub fn detail_form_browse_context() -> ShortcutContext {
    ShortcutContext::new(ContextName::DetailFormBrowse)
        .add(Shortcut::static_msg(
            KeyCombo::plain(KeyCode::Char('j')),
            || Msg::FormFieldDown,
            "Next field",
        ))
        .add(Shortcut::static_msg(
            KeyCombo::plain(KeyCode::Down),
            || Msg::FormFieldDown,
            "Next field",
        ))
        .add(Shortcut::static_msg(
            KeyCombo::plain(KeyCode::Char('k')),
            || Msg::FormFieldUp,
            "Previous field",
        ))
        .add(Shortcut::static_msg(
            KeyCombo::plain(KeyCode::Up),
            || Msg::FormFieldUp,
            "Previous field",
        ))
        .add(Shortcut::static_msg(
            KeyCombo::plain(KeyCode::Enter),
            || Msg::FormFieldActivate,
            "Edit field / toggle bool",
        ))
        .add(Shortcut::static_msg(
            KeyCombo::plain(KeyCode::Char(' ')),
            || Msg::FormFieldActivate,
            "Toggle bool",
        ))
        .add(Shortcut::static_msg(
            KeyCombo::plain(KeyCode::Esc),
            || Msg::FormFieldCancel,
            "Close form",
        ))
        .add(Shortcut::static_msg(
            KeyCombo::plain(KeyCode::Delete),
            || Msg::FormFieldClear,
            "Clear optional field",
        ))
}

/// Detail form edit mode: text input for a single field
pub fn detail_form_edit_context() -> ShortcutContext {
    ShortcutContext::new(ContextName::DetailFormEdit)
        .with_char_handler(|c| Msg::InsertChar(c))
        .add(Shortcut::static_msg(
            KeyCombo::plain(KeyCode::Enter),
            || Msg::FormFieldCommit,
            "Commit field value",
        ))
        .add(Shortcut::static_msg(
            KeyCombo::plain(KeyCode::Esc),
            || Msg::FormFieldCancel,
            "Cancel edit",
        ))
        .add(Shortcut::static_msg(
            KeyCombo::plain(KeyCode::Backspace),
            || Msg::DeleteBack,
            "Delete backward",
        ))
        .add(Shortcut::static_msg(
            KeyCombo::plain(KeyCode::Delete),
            || Msg::DeleteForward,
            "Delete forward",
        ))
        .add(Shortcut::static_msg(
            KeyCombo::plain(KeyCode::Left),
            || Msg::CursorLeft,
            "Move cursor left",
        ))
        .add(Shortcut::static_msg(
            KeyCombo::plain(KeyCode::Right),
            || Msg::CursorRight,
            "Move cursor right",
        ))
        .add(Shortcut::static_msg(
            KeyCombo::plain(KeyCode::Home),
            || Msg::CursorHome,
            "Move cursor to start",
        ))
        .add(Shortcut::static_msg(
            KeyCombo::ctrl('a'),
            || Msg::CursorHome,
            "Move cursor to start",
        ))
        .add(Shortcut::static_msg(
            KeyCombo::plain(KeyCode::End),
            || Msg::CursorEnd,
            "Move cursor to end",
        ))
        .add(Shortcut::static_msg(
            KeyCombo::ctrl('e'),
            || Msg::CursorEnd,
            "Move cursor to end",
        ))
        .add(Shortcut::static_msg(
            KeyCombo::ctrl('u'),
            || Msg::ClearLine,
            "Clear field",
        ))
}

// ═══════════════════════════════════════════════════════════════════════════════
// STACK INITIALIZATION
// ═══════════════════════════════════════════════════════════════════════════════

/// Initialize the shortcut stack with global context
pub fn init_stack() -> ShortcutStack {
    let mut stack = ShortcutStack::new();
    stack.push(global_context());
    stack
}

/// Get the context for a pane type
pub fn context_for_pane(pane_type: crate::model::PaneType) -> Vec<ShortcutContext> {
    use crate::model::PaneType;
    match pane_type {
        PaneType::Agent => vec![text_input_context(), agent_pane_context()],
        PaneType::Canvas => vec![canvas_pane_context()],
        PaneType::Detail => vec![detail_pane_context()],
    }
}

/// Detail pane shortcuts (scroll only)
pub fn detail_pane_context() -> ShortcutContext {
    ShortcutContext::new(ContextName::DetailPane)
        .add(Shortcut::static_msg(
            KeyCombo::plain(KeyCode::Char('j')),
            || Msg::ScrollDown(3),
            "Scroll down",
        ))
        .add(Shortcut::static_msg(
            KeyCombo::plain(KeyCode::Down),
            || Msg::ScrollDown(3),
            "Scroll down",
        ))
        .add(Shortcut::static_msg(
            KeyCombo::plain(KeyCode::Char('k')),
            || Msg::ScrollUp(3),
            "Scroll up",
        ))
        .add(Shortcut::static_msg(
            KeyCombo::plain(KeyCode::Up),
            || Msg::ScrollUp(3),
            "Scroll up",
        ))
        .add(Shortcut::static_msg(
            KeyCombo::plain(KeyCode::PageDown),
            || Msg::ScrollPageDown,
            "Page down",
        ))
        .add(Shortcut::static_msg(
            KeyCombo::plain(KeyCode::PageUp),
            || Msg::ScrollPageUp,
            "Page up",
        ))
}
