use std::sync::{mpsc::Sender, OnceLock};
use ratatui::crossterm::event::{KeyEvent, MouseEvent};

use crate::model::LogLevel;

/// Global message sender - initialized once at startup
static TX: OnceLock<Sender<Msg>> = OnceLock::new();

/// Initialize the global message sender (call once at startup)
pub fn init_sender(tx: Sender<Msg>) {
    TX.set(tx).ok();
}

/// Send a message from anywhere
pub fn send(msg: Msg) {
    if let Some(tx) = TX.get() {
        tx.send(msg).ok();
    }
}

pub use common::tui::layout::{Orientation, PaneId, SplitId};

use crate::model::PaneType;

/// All possible events in the application
#[derive(Debug)]
pub enum Msg {
    // ─────────────────────────────────────────────────────────
    // Input events (raw)
    // ─────────────────────────────────────────────────────────
    Key(KeyEvent),
    Mouse(MouseEvent),

    // ─────────────────────────────────────────────────────────
    // Shortcut-generated events (from shortcut stack)
    // ─────────────────────────────────────────────────────────
    /// Enter pane command mode (Ctrl+W)
    EnterPaneCommand,
    /// Exit pane command mode
    ExitPaneCommand,
    /// Escape key pressed (context-dependent behavior)
    EscapePressed,
    /// Ctrl+C pressed (clear input or quit check)
    CtrlCPressed,

    // Text input shortcuts
    /// Insert a character at cursor
    InsertChar(char),
    /// Delete character before cursor
    DeleteBack,
    /// Delete character after cursor (forward delete)
    DeleteForward,
    /// Move cursor left
    CursorLeft,
    /// Move cursor right
    CursorRight,
    /// Move cursor to start of line
    CursorHome,
    /// Move cursor to end of line
    CursorEnd,
    /// Clear the current line
    ClearLine,

    // Scrolling shortcuts
    /// Scroll up by N lines
    ScrollUp(usize),
    /// Scroll down by N lines
    ScrollDown(usize),
    /// Scroll up one page
    ScrollPageUp,
    /// Scroll down one page
    ScrollPageDown,

    // Agent pane shortcuts
    /// Submit the current input to the agent
    AgentSubmitInput,
    /// Cancel the in-progress agent request
    AgentCancel,

    // Pane command mode shortcuts
    /// Resize the current split (vertical)
    ResizeSplit { delta: i16 },
    /// Resize the current split (horizontal)
    ResizeSplitHorizontal { delta: i16 },
    /// Close the focused pane
    ClosePane,

    // ─────────────────────────────────────────────────────────
    // Pane management
    // ─────────────────────────────────────────────────────────
    /// Create a new split in the focused pane
    Split(Orientation),
    /// Focus a specific pane
    Focus(PaneId),
    /// Close a pane
    Close(PaneId),
    /// Resize a split (delta in terminal cells)
    Resize { split_id: SplitId, delta: i16 },
    /// Cycle focus to next pane
    FocusNext,
    /// Cycle focus to previous pane
    FocusPrev,
    /// Focus pane in direction (vim-style hjkl)
    FocusDirection(Direction),
    /// Switch a pane's type
    SetPaneType { pane_id: PaneId, pane_type: PaneType },

    // ─────────────────────────────────────────────────────────
    // Canvas events
    // ─────────────────────────────────────────────────────────
    CanvasPan { dx: f64, dy: f64 },
    CanvasZoom { delta: f64 },
    CanvasResetView,
    /// Insert a new node after the currently selected canvas node
    InsertAfterSelected,
    /// Insert a new node before the currently selected canvas node
    InsertBeforeSelected,

    // ─────────────────────────────────────────────────────────
    // Playbook
    // ─────────────────────────────────────────────────────────
    /// Load a playbook from disk into model state
    Load { path: String },
    /// Save the current playbook back to its path
    Save,
    /// Add a new empty task set with an ID one higher than the current max integer key
    AddTaskSet,
    /// Add a new task node at a specific index in a task set
    AddNode { set_id: String, op: String, index: usize },
    /// Move a canvas shape to an absolute canvas position
    MoveShape { pane_id: PaneId, shape_id: common::tui::canvas::ShapeId, x: f64, y: f64 },

    // ─────────────────────────────────────────────────────────
    // Task field editor (detail pane form)
    // ─────────────────────────────────────────────────────────
    /// Move highlight to next field
    FormFieldDown,
    /// Move highlight to previous field
    FormFieldUp,
    /// Enter: toggle bool or start text/int editing
    FormFieldActivate,
    /// Enter while editing: commit the current buffer
    FormFieldCommit,
    /// Esc: cancel editing (if active) or close the form
    FormFieldCancel,
    /// Clear an optional field (set to absent)
    FormFieldClear,

    // ─────────────────────────────────────────────────────────
    // Delete
    // ─────────────────────────────────────────────────────────
    /// Delete the currently selected canvas node (task or task set with confirmation)
    DeleteSelected,
    /// Immediately delete a single task node
    DeleteNode { set_id: String, index: usize },
    /// Confirm deletion of a task set (yes)
    ConfirmDeleteTaskSet,
    /// Cancel deletion of a task set (no)
    CancelDeleteTaskSet,
    /// Confirm the currently highlighted delete popup option
    ConfirmDeleteSelected,
    /// Move the highlighted option left
    ConfirmDeleteSelectPrev,
    /// Move the highlighted option right
    ConfirmDeleteSelectNext,

    // ─────────────────────────────────────────────────────────
    // Add-node popup
    // ─────────────────────────────────────────────────────────
    /// Open the add-node popup for a task set at a specific insertion index
    OpenAddNodePopup { set_id: String, index: usize },
    /// Type a character into the popup filter
    AddNodePopupChar(char),
    /// Delete last character from popup filter
    AddNodePopupBackspace,
    /// Move selection up (-1) or down (+1)
    AddNodePopupMove(i32),
    /// Confirm selection and add node
    AddNodePopupConfirm,
    /// Cancel and close the popup
    AddNodePopupCancel,

    // ─────────────────────────────────────────────────────────
    // Generate popup
    // ─────────────────────────────────────────────────────────
    /// Open the generate-payload popup
    Generate,
    /// Move selection up (-1) or down (+1)
    GeneratePopupMove(i32),
    /// Confirm and generate the payload
    GeneratePopupConfirm,
    /// Cancel and close the popup
    GeneratePopupCancel,

    // ─────────────────────────────────────────────────────────
    // File browser popup
    // ─────────────────────────────────────────────────────────
    /// Open the file browser popup
    OpenFileBrowser,
    /// Move selection up/down
    FileBrowserMove(i32),
    /// Enter selected directory or confirm selected file
    FileBrowserEnter,
    /// Go up one directory
    FileBrowserUp,
    /// Close the file browser
    FileBrowserCancel,

    // ─────────────────────────────────────────────────────────
    // New-playbook popup
    // ─────────────────────────────────────────────────────────
    /// Open the new-playbook filename popup
    NewPlaybook,
    /// Type a character into the filename input
    NewPlaybookPopupChar(char),
    /// Delete last character from filename input
    NewPlaybookPopupBackspace,
    /// Confirm and create the playbook file
    NewPlaybookPopupConfirm,
    /// Cancel and close the popup
    NewPlaybookPopupCancel,

    // ─────────────────────────────────────────────────────────
    // Setup wizard popup
    // ─────────────────────────────────────────────────────────
    /// Type a character into the API key input
    WizardChar(char),
    /// Delete last character from API key input
    WizardBackspace,
    /// Confirm and save the entered API key
    WizardSubmit,
    /// Skip the wizard (save empty config and continue)
    WizardSkip,
    /// Move selection up (list steps)
    WizardUp,
    /// Move selection down (list steps)
    WizardDown,

    // ─────────────────────────────────────────────────────────
    // Agent background events
    // ─────────────────────────────────────────────────────────
    /// Text chunk (or tool call summary) from Claude
    AgentResponse { pane_id: PaneId, content: String, role: crate::model::MessageRole },
    /// Claude finished processing
    AgentDone { pane_id: PaneId },
    /// Claude returned an error
    AgentError { pane_id: PaneId, error: String },
    /// Apply a playbook JSON string directly (from agent tool)
    ApplyPlaybookJson { json: String },

    // ─────────────────────────────────────────────────────────
    // Logging
    // ─────────────────────────────────────────────────────────
    Log { level: LogLevel, message: String },

    // ─────────────────────────────────────────────────────────
    // App lifecycle
    // ─────────────────────────────────────────────────────────
    Quit,
    Tick,
    AppInit,
    AppShutdown,
    PaneCreated { pane_id: PaneId, pane_type: PaneType },
    PaneDestroyed { pane_id: PaneId, pane_type: PaneType },
}

impl Msg {
    /// Create a debug log message
    pub fn debug(message: impl Into<String>) -> Self {
        Msg::Log { level: LogLevel::Debug, message: message.into() }
    }

    /// Create an info log message
    pub fn info(message: impl Into<String>) -> Self {
        Msg::Log { level: LogLevel::Info, message: message.into() }
    }

    /// Create a warning log message
    pub fn warn(message: impl Into<String>) -> Self {
        Msg::Log { level: LogLevel::Warn, message: message.into() }
    }

    /// Create an error log message
    pub fn error(message: impl Into<String>) -> Self {
        Msg::Log { level: LogLevel::Error, message: message.into() }
    }
}

/// Direction for focus navigation
#[derive(Debug, Clone, Copy)]
pub enum Direction {
    Up,
    Down,
    Left,
    Right,
}
