use std::collections::HashMap;

use ratatui::layout::Rect;
use ratatui::symbols::Marker;

use common::tui::canvas::{Animator, Connector, DraggableCanvas, LayeredShape, ShapeId};
use common::tui::text::{PaneOutputInfo, TextSelection};

/// What a canvas shape represents in the playbook
#[derive(Debug, Clone)]
pub enum PlaybookRef {
    TaskSetLabel { set_id: String },
    Task { set_id: String, index: usize },
    AddButton { set_id: String },
}
use crate::message::{Orientation, PaneId, SplitId};

pub use common::tui::layout::{LayoutNode, Split};

/// The type of content a pane can display
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaneType {
    Agent,
    Canvas,
    Detail,
}

impl PaneType {
    /// Get all available pane types for tab switching
    pub fn all() -> &'static [PaneType] {
        &[PaneType::Agent, PaneType::Canvas, PaneType::Detail]
    }

    /// Get display name for the pane type
    pub fn name(&self) -> &'static str {
        match self {
            PaneType::Agent => "Agent",
            PaneType::Canvas => "Canvas",
            PaneType::Detail => "Detail",
        }
    }
}

/// A single pane in the layout
#[derive(Debug)]
pub struct Pane {
    pub id: PaneId,
    pub pane_type: PaneType,
}

/// Log level for debug messages
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLevel {
    Debug,
    Info,
    Warn,
    Error,
}

/// Active tab within the agent pane
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AgentTab {
    #[default]
    Chat,
    Debug,
}

/// Role in a conversation message
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageRole {
    User,
    Assistant,
    Tool,
}

/// A single message in the agent conversation
#[derive(Debug, Clone)]
pub struct AgentMessage {
    pub role: MessageRole,
    pub content: String,
}

/// Agent pane state
#[derive(Debug, Clone)]
pub struct AgentState {
    pub input: String,
    /// Byte offset of cursor in `input`
    pub cursor_pos: usize,
    /// Scroll offset from bottom (0 = newest visible, increasing = scrolling up)
    pub scroll: usize,
    /// When true, new messages auto-scroll to bottom
    pub auto_scroll: bool,
    pub active_tab: AgentTab,
    pub messages: Vec<AgentMessage>,
    pub loading: bool,
    pub error: Option<String>,
    pub cached_lines: Vec<ratatui::text::Line<'static>>,
    pub cached_msg_count: usize,
    pub spinner_frame: usize,
    /// Text selection in the output area
    pub selection: common::tui::text::TextSelection,
}

impl Default for AgentState {
    fn default() -> Self {
        Self {
            input: String::new(),
            cursor_pos: 0,
            scroll: 0,
            auto_scroll: true,
            active_tab: AgentTab::default(),
            messages: Vec::new(),
            loading: false,
            error: None,
            cached_lines: Vec::new(),
            cached_msg_count: 0,
            spinner_frame: 0,
            selection: common::tui::text::TextSelection::default(),
        }
    }
}

/// A single debug log entry
pub struct LogEntry {
    pub level: LogLevel,
    pub message: String,
}

/// Shared debug log (accumulated across all sources)
pub struct DebugState {
    pub entries: Vec<LogEntry>,
    pub max_entries: usize,
}

impl DebugState {
    pub fn new() -> Self {
        Self { entries: Vec::new(), max_entries: 1000 }
    }

    pub fn push(&mut self, level: LogLevel, message: impl Into<String>) {
        if self.entries.len() >= self.max_entries {
            self.entries.remove(0);
        }
        self.entries.push(LogEntry { level, message: message.into() });
    }

    pub fn debug(&mut self, msg: impl Into<String>) { self.push(LogLevel::Debug, msg); }
    pub fn info(&mut self, msg: impl Into<String>) { self.push(LogLevel::Info, msg); }
    pub fn warn(&mut self, msg: impl Into<String>) { self.push(LogLevel::Warn, msg); }
    pub fn error(&mut self, msg: impl Into<String>) { self.push(LogLevel::Error, msg); }
}

/// Per-pane debug view state
#[derive(Default)]
pub struct DebugViewState {
    pub scroll: usize,
    pub selection: TextSelection,
}

/// A temporary toast notification
pub struct Toast {
    pub message: String,
    pub expires_at: std::time::Instant,
}

impl Toast {
    pub fn new(message: impl Into<String>, duration: std::time::Duration) -> Self {
        Self {
            message: message.into(),
            expires_at: std::time::Instant::now() + duration,
        }
    }

    pub fn is_expired(&self) -> bool {
        std::time::Instant::now() >= self.expires_at
    }
}

/// Current value of a form field
#[derive(Clone, Debug)]
pub enum FieldValue {
    Text(String),
    Int(String),
    Bool(bool),
    Empty,
}

impl FieldValue {
    pub fn display(&self) -> String {
        match self {
            FieldValue::Text(s) => s.clone(),
            FieldValue::Int(s) => s.clone(),
            FieldValue::Bool(b) => b.to_string(),
            FieldValue::Empty => String::new(),
        }
    }
}

/// Active text-buffer state while editing a field
#[derive(Clone, Debug)]
pub struct FieldEditing {
    pub buffer: String,
    pub cursor: usize,
}

impl FieldEditing {
    pub fn new(initial: &str) -> Self {
        Self { buffer: initial.to_string(), cursor: initial.len() }
    }

    pub fn insert(&mut self, c: char) {
        self.buffer.insert(self.cursor, c);
        self.cursor += c.len_utf8();
    }

    pub fn delete_back(&mut self) {
        if self.cursor == 0 { return; }
        let prev = self.buffer[..self.cursor]
            .char_indices()
            .last()
            .map(|(i, _)| i)
            .unwrap_or(0);
        self.buffer.remove(prev);
        self.cursor = prev;
    }

    pub fn move_left(&mut self) {
        if self.cursor == 0 { return; }
        self.cursor = self.buffer[..self.cursor]
            .char_indices()
            .last()
            .map(|(i, _)| i)
            .unwrap_or(0);
    }

    pub fn move_right(&mut self) {
        if self.cursor >= self.buffer.len() { return; }
        let next = self.buffer[self.cursor..]
            .char_indices()
            .nth(1)
            .map(|(i, _)| self.cursor + i)
            .unwrap_or(self.buffer.len());
        self.cursor = next;
    }

    pub fn delete_forward(&mut self) {
        if self.cursor >= self.buffer.len() { return; }
        let char_bytes = self.buffer[self.cursor..]
            .chars().next().map(|c| c.len_utf8()).unwrap_or(0);
        if char_bytes > 0 {
            self.buffer.remove(self.cursor);
        }
    }
}

/// State for a single editable field in the task form
#[derive(Clone, Debug)]
pub struct FieldEditState {
    pub name: &'static str,
    pub type_hint: &'static str,
    pub required: bool,
    pub value: FieldValue,
    /// Some when this field is being actively text-edited
    pub editing: Option<FieldEditing>,
}

/// State for the task editor form shown in the detail pane
pub struct TaskEditState {
    pub set_id: String,
    pub index: usize,
    pub fields: Vec<FieldEditState>,
    /// Which field row is highlighted (0-based)
    pub selected: usize,
}

/// State for the confirm-delete-task-set popup
pub struct ConfirmDeleteState {
    pub set_id: String,
    /// Index of highlighted option (0=Yes, 1=Cancel)
    pub selected: usize,
}

/// State for the generate-payload popup (Shellcode / EXE / DLL)
pub struct GeneratePopupState {
    pub selected: usize,
}

/// State for the new-playbook filename popup
pub struct NewPlaybookPopupState {
    pub filename: String,
    pub cursor: usize,
    /// When true, confirm writes the current in-memory playbook instead of a blank one
    pub save_as: bool,
}

pub use common::tui::file_browser::FileBrowserState;

/// State for the add-node popup (op selection)
pub struct AddNodePopupState {
    /// Which task set to add the new node to
    pub set_id: String,
    /// Insertion index within the task set (existing nodes at >= index shift right)
    pub index: usize,
    /// Current filter string (user is typing)
    pub filter: String,
    /// Byte-offset cursor within `filter`
    pub cursor: usize,
    /// Highlighted index within the filtered list
    pub selected: usize,
    /// Scroll offset within the filtered list
    pub scroll: usize,
}

/// Canvas-specific state
pub struct CanvasState {
    pub canvas: DraggableCanvas,
    pub shapes: Vec<LayeredShape>,
    pub connectors: Vec<Connector>,
    /// Currently dragged shape: (id, start_mouse_cx, start_mouse_cy, start_shape_x, start_shape_y)
    pub dragging_shape: Option<(ShapeId, f64, f64, f64, f64)>,
    /// When dragging a TaskSetLabel: all shapes in the set with their start positions
    pub dragging_group: Vec<(ShapeId, f64, f64)>,
    /// Initial center of the selection indicator at group-drag start (sel_id, cx, cy)
    pub dragging_group_indicator: Option<(ShapeId, f64, f64)>,
    /// Maps shape ID → what playbook entity it represents
    pub shape_refs: HashMap<ShapeId, PlaybookRef>,
    /// Drives time-based animations (selection indicator, etc.)
    pub animator: Animator,
}

impl CanvasState {
    pub fn new() -> Self {
        // Smaller coordinate space so nodes are visible in the canvas pane
        let mut canvas = DraggableCanvas::new(100.0, 30.0);
        canvas.min_zoom = 0.1;
        canvas.max_zoom = 20.0;
        canvas.set_layer_marker(0, Marker::Braille);
        canvas.set_layer_marker(1, Marker::HalfBlock);
        canvas.set_layer_marker(2, Marker::HalfBlock);
        Self { canvas, shapes: Vec::new(), connectors: Vec::new(), dragging_shape: None, dragging_group: Vec::new(), dragging_group_indicator: None, shape_refs: HashMap::new(), animator: Animator::new() }
    }
}

impl Default for CanvasState {
    fn default() -> Self {
        Self::new()
    }
}

/// State for the first-run API key wizard popup
#[derive(Debug, Clone, Default)]
pub struct WizardPopupState {
    pub input: String,
    pub cursor: usize,
    pub selected: usize,
}

/// Which step of the first-run wizard we're on
#[derive(Debug, Clone, Default, PartialEq)]
pub enum WizardStep {
    #[default]
    Provider,
    OllamaHost,
    OllamaPort,
    OllamaModel,
    ClaudeApiKey,
}

/// Collected values across wizard steps
#[derive(Debug, Clone, Default)]
pub struct WizardData {
    pub provider: String,
    pub ollama_host: String,
    pub ollama_port: String,
    pub ollama_model: String,
    pub api_key: String,
}

/// The complete application state
pub struct Model {
    // ─────────────────────────────────────────────────────────
    // Layout state
    // ─────────────────────────────────────────────────────────
    pub panes: Vec<Pane>,
    pub splits: Vec<Split>,
    pub root: LayoutNode,
    pub focused: PaneId,

    // ─────────────────────────────────────────────────────────
    // Pane-specific state (keyed by PaneId)
    // ─────────────────────────────────────────────────────────
    pub agent_states: HashMap<PaneId, AgentState>,
    pub canvas_states: HashMap<PaneId, CanvasState>,
    pub debug_state: DebugState,
    pub debug_view_states: HashMap<PaneId, DebugViewState>,
    /// Cached pane output areas for mouse selection (updated during render)
    pub pane_output_info: HashMap<PaneId, PaneOutputInfo>,

    // ─────────────────────────────────────────────────────────
    // Playbook
    // ─────────────────────────────────────────────────────────
    pub playbook: Option<common::Playbook>,
    pub playbook_path: Option<String>,

    // ─────────────────────────────────────────────────────────
    // Popups
    // ─────────────────────────────────────────────────────────
    /// Add-node op-selection popup state (None = closed)
    pub add_node_popup: Option<AddNodePopupState>,
    /// Confirm-delete-task-set popup state (None = closed)
    pub confirm_delete: Option<ConfirmDeleteState>,
    /// Generate-payload popup state (None = closed)
    pub generate_popup: Option<GeneratePopupState>,
    /// New-playbook filename popup state (None = closed)
    pub new_playbook_popup: Option<NewPlaybookPopupState>,
    /// Open-file browser state (None = closed)
    pub file_browser: Option<FileBrowserState>,
    /// First-run setup wizard popup state (None = closed / wizard complete)
    pub wizard_popup: Option<WizardPopupState>,
    pub wizard_step: WizardStep,
    pub wizard_data: WizardData,
    /// Task field editor state (Some when a Task node is selected)
    pub task_edit: Option<TaskEditState>,

    // ─────────────────────────────────────────────────────────
    // Selection
    // ─────────────────────────────────────────────────────────
    /// The currently selected node: (canvas_pane_id, shape_id)
    pub selected_node: Option<(PaneId, ShapeId)>,
    /// The selection indicator shape id (so we can remove it)
    pub selection_indicator_id: Option<ShapeId>,

    // ─────────────────────────────────────────────────────────
    // Detail pane
    // ─────────────────────────────────────────────────────────
    /// Scroll offset for the detail pane
    pub detail_scroll: usize,
    /// Text selection state for the detail pane
    pub detail_selection: common::tui::text::TextSelection,

    // ─────────────────────────────────────────────────────────
    // App state
    // ─────────────────────────────────────────────────────────
    pub running: bool,
    pub needs_redraw: bool,
    pub next_pane_id: PaneId,
    pub next_split_id: SplitId,

    /// Terminal size (width, height) - updated during render
    pub terminal_size: (u16, u16),
    /// Cached pane areas for mouse hit testing (updated during render)
    pub pane_areas: HashMap<PaneId, Rect>,
    /// Cached split border areas for resize: (split_id, orientation, border_rect, parent_area)
    pub split_borders: Vec<(SplitId, Orientation, Rect, Rect)>,
    /// Currently dragging a split border
    pub resizing_split: Option<SplitId>,
    /// Last Ctrl+C press time (for double-press to quit)
    pub last_ctrl_c: Option<std::time::Instant>,
    /// Active toast notification (shown as overlay)
    pub toast: Option<Toast>,
    /// Cached tab areas for agent panes: (pane_id, tab, rect)
    pub tab_areas: Vec<(PaneId, AgentTab, Rect)>,

    /// Channel for sending messages from anywhere
    pub tx: std::sync::mpsc::Sender<crate::message::Msg>,
    pub rx: std::sync::mpsc::Receiver<crate::message::Msg>,

    // ─────────────────────────────────────────────────────────
    // Shortcut system
    // ─────────────────────────────────────────────────────────
    pub shortcut_stack: crate::shortcuts::ShortcutStack,
}

impl Model {
    pub fn new() -> Self {
        // Create channel for messages from anywhere
        let (tx, rx) = std::sync::mpsc::channel();

        // Initialize global sender so anyone can call message::send()
        crate::message::init_sender(tx.clone());

        // Pane 1 = Canvas, Pane 2 = Agent, Pane 3 = Detail
        let pane1 = Pane { id: 1, pane_type: PaneType::Canvas };
        let pane2 = Pane { id: 2, pane_type: PaneType::Agent };
        let pane3 = Pane { id: 3, pane_type: PaneType::Detail };

        // Split 2 = Vertical (canvas left 2/3, detail right 1/3)
        let split2 = Split {
            id: 2,
            orientation: Orientation::Vertical,
            ratio: 0.67,
            first: LayoutNode::Pane(1),
            second: LayoutNode::Pane(3),
        };

        // Split 1 = Horizontal (canvas+detail top, agent bottom), ratio 0.65
        let split1 = Split {
            id: 1,
            orientation: Orientation::Horizontal,
            ratio: 0.65,
            first: LayoutNode::Split(2),
            second: LayoutNode::Pane(2),
        };

        let mut canvas_states = HashMap::new();
        canvas_states.insert(1, CanvasState::new());

        // Initialize shortcut stack: global + canvas pane contexts (pane 1 is focused)
        let mut shortcut_stack = crate::shortcuts::init_stack();
        for ctx in crate::shortcuts::context_for_pane(PaneType::Canvas) {
            shortcut_stack.push(ctx);
        }

        Self {
            panes: vec![pane1, pane2, pane3],
            splits: vec![split1, split2],
            root: LayoutNode::Split(1),
            focused: 1,

            agent_states: HashMap::new(),
            canvas_states,
            debug_state: DebugState::new(),
            debug_view_states: HashMap::new(),
            pane_output_info: HashMap::new(),

            playbook: None,
            playbook_path: None,

            add_node_popup: None,
            confirm_delete: None,
            generate_popup: None,
            new_playbook_popup: None,
            file_browser: None,
            wizard_popup: None,
            wizard_step: WizardStep::default(),
            wizard_data: WizardData::default(),
            task_edit: None,

            selected_node: None,
            selection_indicator_id: None,

            detail_scroll: 0,
            detail_selection: common::tui::text::TextSelection::default(),

            running: true,
            needs_redraw: true,
            next_pane_id: 4,
            next_split_id: 3,

            terminal_size: (80, 24),
            pane_areas: HashMap::new(),
            split_borders: Vec::new(),
            resizing_split: None,
            last_ctrl_c: None,
            toast: None,
            tab_areas: Vec::new(),

            tx,
            rx,
            shortcut_stack,
        }
    }

    /// Get a pane by ID
    pub fn get_pane(&self, id: PaneId) -> Option<&Pane> {
        self.panes.iter().find(|p| p.id == id)
    }

    /// Get the focused pane
    pub fn focused_pane(&self) -> Option<&Pane> {
        self.get_pane(self.focused)
    }

    /// Get the type of the focused pane
    pub fn focused_pane_type(&self) -> Option<PaneType> {
        self.focused_pane().map(|p| p.pane_type)
    }

    /// Generate next pane ID
    pub fn next_pane_id(&mut self) -> PaneId {
        let id = self.next_pane_id;
        self.next_pane_id += 1;
        id
    }

    /// Generate next split ID
    pub fn next_split_id(&mut self) -> SplitId {
        let id = self.next_split_id;
        self.next_split_id += 1;
        id
    }

    /// Get all pane IDs in order (for focus cycling)
    pub fn pane_ids(&self) -> Vec<PaneId> {
        self.panes.iter().map(|p| p.id).collect()
    }
}

impl Default for Model {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for Model {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Model")
            .field("panes", &self.panes)
            .field("focused", &self.focused)
            .field("running", &self.running)
            .finish()
    }
}
