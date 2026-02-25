// Shape infrastructure - variants and methods kept for future use
#![allow(dead_code)]

use std::cell::Cell;

use ratatui::{
    style::Color,
    widgets::canvas::{Circle as CanvasCircle, Line as CanvasLine, Painter, Rectangle, Shape},
};

// Optimal fill step in canvas units (set by renderer based on viewport/zoom)
thread_local! {
    static FILL_STEP: Cell<f64> = const { Cell::new(0.1) };
}

/// Set the fill step for shape rendering (call before drawing shapes)
pub fn set_fill_step(step: f64) {
    FILL_STEP.with(|s| s.set(step));
}

/// Get the current fill step
fn fill_step() -> f64 {
    FILL_STEP.with(|s| s.get())
}

// ═══════════════════════════════════════════════════════════════════════════════
// PINNED INDICATORS - Shapes that attach to and follow a parent shape
// ═══════════════════════════════════════════════════════════════════════════════

/// Where to anchor pinned indicators relative to the parent shape
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Anchor {
    TopLeft,
    TopRight,
    #[default]
    BottomRight,
    BottomLeft,
    CenterRight,
    CenterLeft,
}

/// Direction to stack multiple indicators
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum StackDirection {
    #[default]
    Vertical,
    Horizontal,
}

/// Content for an indicator - either static text or animated spinner
#[derive(Clone, Debug)]
pub enum IndicatorContent {
    /// Static text that doesn't change
    Static(String),
    /// Animated spinner that cycles through frames
    Spinner {
        frames: Vec<String>,
        interval_ms: u64,
        start: std::time::Instant,
    },
}

/// A single indicator item (bullet point, spinner, etc.)
#[derive(Clone, Debug)]
pub struct Indicator {
    /// Unique identifier for this indicator (e.g., implant ID)
    pub id: String,
    /// Content to display
    pub content: IndicatorContent,
    /// Color of the indicator
    pub color: Color,
}

impl Indicator {
    pub fn new(id: impl Into<String>, text: impl Into<String>, color: Color) -> Self {
        Self {
            id: id.into(),
            content: IndicatorContent::Static(text.into()),
            color,
        }
    }

    /// Create a spinner indicator
    pub fn spinner(id: impl Into<String>, frames: &[&str], interval_ms: u64, color: Color) -> Self {
        Self {
            id: id.into(),
            content: IndicatorContent::Spinner {
                frames: frames.iter().map(|s| s.to_string()).collect(),
                interval_ms,
                start: std::time::Instant::now(),
            },
            color,
        }
    }

    /// Braille spinner (smooth rotation)
    pub fn braille_spinner(id: impl Into<String>, color: Color) -> Self {
        Self::spinner(id, &["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"], 80, color)
    }

    /// Braille spinner with active/inactive color
    pub fn braille_spinner_status(id: impl Into<String>, active: bool) -> Self {
        let color = if active { Color::White } else { Color::DarkGray };
        if active {
            Self::braille_spinner(id, color)
        } else {
            // Inactive: show static dot instead of spinner
            Self::new(id, "○", color)
        }
    }

    /// Dots spinner (vertical dots)
    pub fn dots_spinner(id: impl Into<String>, color: Color) -> Self {
        Self::spinner(id, &["⠄", "⠂", "⠁", "⠈", "⠐", "⠠"], 100, color)
    }

    /// Pulse indicator (alternating filled/empty)
    pub fn pulse(id: impl Into<String>, color: Color) -> Self {
        Self::spinner(id, &["●", "○"], 500, color)
    }

    /// Create a bullet indicator
    pub fn bullet(id: impl Into<String>, color: Color) -> Self {
        Self::new(id, "●", color)
    }

    /// Create a bullet indicator (active = white, inactive = gray)
    pub fn bullet_status(id: impl Into<String>, active: bool) -> Self {
        let color = if active { Color::White } else { Color::DarkGray };
        Self::bullet(id, color)
    }

    /// Create a dot status indicator (filled ● if active, empty ○ if inactive)
    pub fn dot_status(id: impl Into<String>, active: bool) -> Self {
        if active {
            Self::new(id, "●", Color::White)
        } else {
            Self::new(id, "○", Color::DarkGray)
        }
    }

    /// Get the current text to display (handles animation)
    pub fn current_text(&self) -> &str {
        match &self.content {
            IndicatorContent::Static(text) => text,
            IndicatorContent::Spinner { frames, interval_ms, start } => {
                let elapsed = start.elapsed().as_millis() as u64;
                let frame_idx = (elapsed / interval_ms) as usize % frames.len();
                &frames[frame_idx]
            }
        }
    }
}

/// A group of indicators pinned to a parent shape
#[derive(Clone, Debug)]
pub struct PinnedIndicators {
    /// ID of the parent shape this is pinned to
    pub parent_id: ShapeId,
    /// Where to anchor relative to parent
    pub anchor: Anchor,
    /// Direction to stack indicators
    pub stack_direction: StackDirection,
    /// Padding from the parent shape edge
    pub padding: f64,
    /// Spacing between stacked indicators
    pub spacing: f64,
    /// The indicators in this group
    pub indicators: Vec<Indicator>,
}

impl PinnedIndicators {
    pub fn new(parent_id: ShapeId) -> Self {
        Self {
            parent_id,
            anchor: Anchor::default(),
            stack_direction: StackDirection::default(),
            padding: 2.0,
            spacing: 2.0,
            indicators: Vec::new(),
        }
    }

    pub fn with_anchor(mut self, anchor: Anchor) -> Self {
        self.anchor = anchor;
        self
    }

    pub fn with_stack_direction(mut self, direction: StackDirection) -> Self {
        self.stack_direction = direction;
        self
    }

    pub fn with_padding(mut self, padding: f64) -> Self {
        self.padding = padding;
        self
    }

    pub fn with_spacing(mut self, spacing: f64) -> Self {
        self.spacing = spacing;
        self
    }

    /// Add an indicator to the group
    pub fn add(&mut self, indicator: Indicator) {
        self.indicators.push(indicator);
    }

    /// Remove an indicator by ID
    pub fn remove(&mut self, id: &str) -> bool {
        let before = self.indicators.len();
        self.indicators.retain(|i| i.id != id);
        self.indicators.len() != before
    }

    /// Update an indicator by ID, returns true if found
    pub fn update(&mut self, id: &str, color: Color) -> bool {
        if let Some(indicator) = self.indicators.iter_mut().find(|i| i.id == id) {
            indicator.color = color;
            true
        } else {
            false
        }
    }

    /// Set the active status of an indicator (white if active, gray if not)
    pub fn set_active(&mut self, id: &str, active: bool) {
        let color = if active { Color::White } else { Color::DarkGray };
        self.update(id, color);
    }

    /// Calculate positions for all indicators given parent bounds
    /// Returns Vec of (x, y, text, color) for each indicator
    pub fn calculate_positions(&self, parent_bounds: (f64, f64, f64, f64)) -> Vec<(f64, f64, &str, Color)> {
        let (px, py, pw, ph) = parent_bounds;

        // Calculate anchor point on parent
        let (anchor_x, anchor_y) = match self.anchor {
            Anchor::TopLeft => (px - self.padding, py + ph),
            Anchor::TopRight => (px + pw + self.padding, py + ph),
            Anchor::BottomRight => (px + pw + self.padding, py),
            Anchor::BottomLeft => (px - self.padding, py),
            Anchor::CenterRight => (px + pw + self.padding, py + ph / 2.0),
            Anchor::CenterLeft => (px - self.padding, py + ph / 2.0),
        };

        let mut positions = Vec::new();

        for (i, indicator) in self.indicators.iter().enumerate() {
            let offset = i as f64 * self.spacing;

            let (x, y) = match self.stack_direction {
                StackDirection::Vertical => {
                    // Stack downward (in canvas coords, negative Y is down)
                    (anchor_x, anchor_y - offset)
                }
                StackDirection::Horizontal => {
                    // Stack rightward
                    (anchor_x + offset, anchor_y)
                }
            };

            positions.push((x, y, indicator.current_text(), indicator.color));
        }

        positions
    }
}

/// Vertical position for a label
#[derive(Clone, Copy, Default)]
pub enum LabelPosition {
    Top,
    #[default]
    Middle,
    Bottom,
}

/// An optional label for a shape — holds a fully styled multi-line `Text` for rendering
#[derive(Clone)]
pub struct Label {
    pub text: ratatui::text::Text<'static>,
    pub position: LabelPosition,
}

impl Default for Label {
    fn default() -> Self {
        Self::new("")
    }
}

impl Label {
    pub fn new(s: impl Into<String>) -> Self {
        Self {
            text: ratatui::text::Text::from(ratatui::text::Line::from(
                ratatui::text::Span::styled(
                    s.into(),
                    ratatui::style::Style::default().fg(Color::White),
                ),
            )),
            position: LabelPosition::Middle,
        }
    }

    pub fn top(s: impl Into<String>) -> Self {
        Self {
            text: ratatui::text::Text::from(ratatui::text::Line::from(
                ratatui::text::Span::styled(
                    s.into(),
                    ratatui::style::Style::default().fg(Color::White),
                ),
            )),
            position: LabelPosition::Top,
        }
    }

    pub fn bottom(s: impl Into<String>) -> Self {
        Self {
            text: ratatui::text::Text::from(ratatui::text::Line::from(
                ratatui::text::Span::styled(
                    s.into(),
                    ratatui::style::Style::default().fg(Color::White),
                ),
            )),
            position: LabelPosition::Bottom,
        }
    }

    /// Build a label from a pre-constructed multi-line `Text`.
    pub fn from_text(text: ratatui::text::Text<'static>, position: LabelPosition) -> Self {
        Self { text, position }
    }
}

/// Unique identifier for shapes
pub type ShapeId = u32;

/// Global shape ID counter
static NEXT_SHAPE_ID: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(1);

/// Entrance animation effect - shapes coalesce from glitch noise
#[derive(Clone)]
pub struct EntranceEffect {
    pub start: std::time::Instant,
    pub duration: std::time::Duration,
    pub seed: u64,
}

impl EntranceEffect {
    pub fn new() -> Self {
        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;
        Self {
            start: std::time::Instant::now(),
            duration: std::time::Duration::from_millis(800),
            seed,
        }
    }

    /// Get animation progress (0.0 = just started, 1.0 = complete)
    pub fn progress(&self) -> f64 {
        (self.start.elapsed().as_secs_f64() / self.duration.as_secs_f64()).clamp(0.0, 1.0)
    }

    /// Is the animation complete?
    pub fn is_complete(&self) -> bool {
        self.start.elapsed() >= self.duration
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// SELECTION INDICATOR - Corner brackets around selected shapes
// ═══════════════════════════════════════════════════════════════════════════════

/// A selection indicator with L-shaped corners at top-left and bottom-right
#[derive(Clone)]
pub struct SelectionIndicator {
    /// Center X coordinate
    pub cx: f64,
    /// Center Y coordinate
    pub cy: f64,
    /// Width of the selection box
    pub width: f64,
    /// Height of the selection box
    pub height: f64,
    /// Color of the corner brackets
    pub color: Color,
    /// Length of each L arm (as fraction of smaller dimension)
    pub arm_ratio: f64,
}

impl SelectionIndicator {
    pub fn new(cx: f64, cy: f64, width: f64, height: f64, color: Color) -> Self {
        Self {
            cx,
            cy,
            width,
            height,
            color,
            arm_ratio: 0.25,
        }
    }
}

impl Shape for SelectionIndicator {
    fn draw(&self, painter: &mut Painter) {
        let x1 = self.cx - self.width / 2.0;
        let y1 = self.cy + self.height / 2.0;
        let x2 = self.cx + self.width / 2.0;
        let y2 = self.cy + self.height / 2.0;
        let x3 = self.cx + self.width / 2.0;
        let y3 = self.cy - self.height / 2.0;
        let x4 = self.cx - self.width / 2.0;
        let y4 = self.cy - self.height / 2.0;

        // Arm length based on smaller dimension
        let arm = self.width.min(self.height) * self.arm_ratio;

        // Top-left L: horizontal right, vertical down
        CanvasLine { x1, y1, x2: x1 + arm, y2: y1, color: self.color }.draw(painter);
        CanvasLine { x1, y1, x2: x1, y2: y1 - arm, color: self.color }.draw(painter);

        // Top-right
        CanvasLine { x1: x2, y1: y2, x2: x2 - arm, y2, color: self.color }.draw(painter);
        CanvasLine { x1: x2, y1: y2, x2, y2: y2 - arm, color: self.color }.draw(painter);

        // Bottom-right
        CanvasLine { x1:x3, y1: y3, x2: x3-arm, y2: y3, color: self.color }.draw(painter);
        CanvasLine { x1:x3, y1: y3, x2: x3, y2: y3 + arm, color: self.color }.draw(painter);

        //bottom left
        CanvasLine { x1:x4, y1: y4, x2: x4+arm, y2: y4, color: self.color }.draw(painter);
        CanvasLine { x1:x4, y1: y4, x2: x4, y2: y4 + arm, color: self.color }.draw(painter);
    }
}

/// A shape with a layer assignment and unique ID
#[derive(Clone)]
pub struct LayeredShape {
    pub id: ShapeId,
    pub shape: ShapeKind,
    pub layer: u8,
    pub label: Option<Label>,
    /// Entrance animation (coalesce from glitch noise)
    pub entrance: Option<EntranceEffect>,
}

impl LayeredShape {
    pub fn new(shape: ShapeKind, layer: u8) -> Self {
        let id = NEXT_SHAPE_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Self { id, shape, layer, label: None, entrance: Some(EntranceEffect::new()) }
    }

    pub fn with_label(mut self, label: Label) -> Self {
        self.label = Some(label);
        self
    }
}

/// Flow animation for connectors - creates moving segments
#[derive(Clone)]
pub struct Flow {
    /// Length of each segment (0.0 to 1.0)
    pub segment_length: f64,
    /// Gap between segments (0.0 to 1.0)
    pub gap: f64,
    /// Speed in full line lengths per second
    pub speed: f64,
    /// Reverse direction (flow from 'to' to 'from')
    pub reverse: bool,
}

impl Default for Flow {
    fn default() -> Self {
        Self {
            segment_length: 0.15,
            gap: 0.15,
            speed: 0.5,
            reverse: false,
        }
    }
}

impl Flow {
    /// Fast flowing data (e.g., active transfer)
    pub fn fast() -> Self {
        Self {
            speed: 1.0,
            ..Default::default()
        }
    }

    /// Slow flowing data (e.g., idle/heartbeat)
    pub fn slow() -> Self {
        Self {
            speed: 0.2,
            ..Default::default()
        }
    }

    /// Dense segments (more visible)
    pub fn dense() -> Self {
        Self {
            segment_length: 0.2,
            gap: 0.05,
            ..Default::default()
        }
    }

    /// Sparse segments (dotted appearance)
    pub fn sparse() -> Self {
        Self {
            segment_length: 0.05,
            gap: 0.2,
            ..Default::default()
        }
    }

    /// Reverse the flow direction
    pub fn reversed(mut self) -> Self {
        self.reverse = true;
        self
    }

    /// Set custom speed
    pub fn with_speed(mut self, speed: f64) -> Self {
        self.speed = speed;
        self
    }
}

/// A connector between two shapes - draws a line between their centers
#[derive(Clone)]
pub struct Connector {
    pub from: ShapeId,
    pub to: ShapeId,
    pub color: Color,
    /// Start percentage along the line (0.0 = from center, 1.0 = to center)
    pub start_percent: f64,
    /// End percentage along the line (0.0 = from center, 1.0 = to center)
    pub end_percent: f64,
    /// Optional flow animation
    pub flow: Option<Flow>,
    /// Start time for flow animation
    flow_start: std::time::Instant,
}

impl Connector {
    pub fn new(from: ShapeId, to: ShapeId) -> Self {
        Self {
            from,
            to,
            color: Color::White,
            start_percent: 0.0,
            end_percent: 1.0,
            flow: None,
            flow_start: std::time::Instant::now(),
        }
    }

    pub fn with_flow(mut self, flow: Flow) -> Self {
        self.flow = Some(flow);
        self.flow_start = std::time::Instant::now();
        self
    }

    pub fn with_color(mut self, color: Color) -> Self {
        self.color = color;
        self
    }

    /// Set start and end percentages (for partial/animated lines)
    pub fn with_range(mut self, start: f64, end: f64) -> Self {
        self.start_percent = start.clamp(0.0, 1.0);
        self.end_percent = end.clamp(0.0, 1.0);
        self
    }

    /// Create a static (non-flowing) connector
    pub fn static_line(from: ShapeId, to: ShapeId, color: Color) -> Self {
        Self::new(from, to).with_color(color)
    }

    /// Create a flowing connector with default settings
    pub fn flowing(from: ShapeId, to: ShapeId, color: Color) -> Self {
        Self::new(from, to)
            .with_color(color)
            .with_flow(Flow::default())
    }

    /// Create a flowing connector with custom speed
    pub fn flowing_with_speed(from: ShapeId, to: ShapeId, color: Color, speed: f64) -> Self {
        Self::new(from, to)
            .with_color(color)
            .with_flow(Flow {
                speed,
                ..Flow::default()
            })
    }

    /// Get the segments to draw for this connector.
    /// Returns a list of (start_percent, end_percent) tuples.
    pub fn get_segments(&self) -> Vec<(f64, f64)> {
        match &self.flow {
            None => {
                // Static line
                vec![(self.start_percent, self.end_percent)]
            }
            Some(flow) => {
                let elapsed = self.flow_start.elapsed().as_secs_f64();
                let cycle_length = flow.segment_length + flow.gap;

                // Calculate offset based on time
                let offset = (elapsed * flow.speed) % cycle_length;
                let offset = if flow.reverse { -offset } else { offset };

                let mut segments = Vec::new();

                // Generate segments that cover the visible range
                let mut pos = -cycle_length + offset;
                while pos < 1.0 + flow.segment_length {
                    let seg_start = pos;
                    let seg_end = pos + flow.segment_length;

                    // Clamp to visible range and apply start/end percent limits
                    let clamped_start = seg_start.max(self.start_percent).min(self.end_percent);
                    let clamped_end = seg_end.max(self.start_percent).min(self.end_percent);

                    if clamped_end > clamped_start {
                        segments.push((clamped_start, clamped_end));
                    }

                    pos += cycle_length;
                }

                segments
            }
        }
    }
}

/// Wrapper enum for different shape types
#[derive(Clone)]
pub enum ShapeKind {
    Monitor(Monitor),
    Circle(Circle),
    Robot(Robot),
    Server(Server),
    SelectionIndicator(SelectionIndicator),
    Node(Node),
}

impl ShapeKind {
    /// Check if a point is inside this shape
    pub fn contains(&self, x: f64, y: f64) -> bool {
        match self {
            ShapeKind::Monitor(m) => {
                x >= m.x && x <= m.x + m.width &&
                y >= m.y && y <= m.y + m.height
            }
            ShapeKind::Circle(c) => {
                let dx = x - c.x;
                let dy = y - c.y;
                dx * dx + dy * dy <= c.radius * c.radius
            }
            ShapeKind::Robot(r) => {
                x >= r.x && x <= r.x + r.width &&
                y >= r.y && y <= r.y + r.height
            }
            ShapeKind::Server(s) => {
                x >= s.x && x <= s.x + s.width &&
                y >= s.y && y <= s.y + s.height
            }
            ShapeKind::SelectionIndicator(si) => {
                let x1 = si.cx - si.width / 2.0;
                let y1 = si.cy - si.height / 2.0;
                x >= x1 && x <= x1 + si.width &&
                y >= y1 && y <= y1 + si.height
            }
            ShapeKind::Node(n) => {
                x >= n.x && x <= n.x + n.width &&
                y >= n.y && y <= n.y + n.height
            }
        }
    }

    /// Get the position of this shape (top-left corner for rectangles, center for circles)
    pub fn position(&self) -> (f64, f64) {
        match self {
            ShapeKind::Monitor(m) => (m.x, m.y),
            ShapeKind::Circle(c) => (c.x - c.radius, c.y - c.radius),
            ShapeKind::Robot(r) => (r.x, r.y),
            ShapeKind::Server(s) => (s.x, s.y),
            ShapeKind::SelectionIndicator(si) => (si.cx - si.width / 2.0, si.cy - si.height / 2.0),
            ShapeKind::Node(n) => (n.x, n.y),
        }
    }

    /// Get the center of this shape
    pub fn center(&self) -> (f64, f64) {
        match self {
            ShapeKind::Monitor(m) => (m.x + m.width / 2.0, m.y + m.height / 2.0),
            ShapeKind::Circle(c) => (c.x, c.y),
            ShapeKind::Robot(r) => (r.x + r.width / 2.0, r.y + r.height / 2.0),
            ShapeKind::Server(s) => (s.x + s.width / 2.0, s.y + s.height / 2.0),
            ShapeKind::SelectionIndicator(si) => (si.cx, si.cy),
            ShapeKind::Node(n) => (n.x + n.width / 2.0, n.y + n.height / 2.0),
        }
    }

    /// Set the position of this shape
    pub fn set_position(&mut self, x: f64, y: f64) {
        match self {
            ShapeKind::Monitor(m) => {
                m.x = x;
                m.y = y;
            }
            ShapeKind::Circle(c) => {
                c.x = x + c.radius;
                c.y = y + c.radius;
            }
            ShapeKind::Robot(r) => {
                r.x = x;
                r.y = y;
            }
            ShapeKind::Server(s) => {
                s.x = x;
                s.y = y;
            }
            ShapeKind::SelectionIndicator(si) => {
                // x,y is top-left, so convert to center
                si.cx = x + si.width / 2.0;
                si.cy = y + si.height / 2.0;
            }
            ShapeKind::Node(n) => {
                n.x = x;
                n.y = y;
            }
        }
    }

    /// Get bounding box (x, y, width, height)
    pub fn bounds(&self) -> (f64, f64, f64, f64) {
        match self {
            ShapeKind::Monitor(m) => {
                // Include stand: neck_height = 0.13 * width extends below y
                let neck_height = 0.13 * m.width;
                (m.x, m.y - neck_height, m.width, m.height + neck_height)
            }
            ShapeKind::Circle(c) => (c.x - c.radius, c.y - c.radius, c.radius * 2.0, c.radius * 2.0),
            ShapeKind::Robot(r) => {
                // Ball extends ~1.8% beyond stated height
                let extra = r.height * 0.02;
                (r.x, r.y, r.width, r.height + extra)
            }
            ShapeKind::Server(s) => (s.x, s.y, s.width, s.height),
            ShapeKind::SelectionIndicator(si) => (si.cx - si.width / 2.0, si.cy - si.height / 2.0, si.width, si.height),
            ShapeKind::Node(n) => (n.x, n.y, n.width, n.height),
        }
    }

    /// Get the label position for this shape
    pub fn label_position(&self, pos: LabelPosition) -> (f64, f64) {
        let (x, y, w, h) = self.bounds();
        let cx = x + w / 2.0;
        match pos {
            LabelPosition::Top => (cx, y + h - 1.0),
            LabelPosition::Middle => (cx, y + h / 2.0),
            LabelPosition::Bottom => (cx, y + 1.0),
        }
    }
}

impl Shape for ShapeKind {
    fn draw(&self, painter: &mut Painter) {
        match self {
            ShapeKind::Monitor(m) => m.draw(painter),
            ShapeKind::Circle(c) => c.draw(painter),
            ShapeKind::Robot(r) => r.draw(painter),
            ShapeKind::Server(s) => s.draw(painter),
            ShapeKind::SelectionIndicator(si) => si.draw(painter),
            ShapeKind::Node(n) => n.draw(painter),
        }
    }
}

/// A computer monitor icon made of canvas primitives
#[derive(Clone)]
pub struct Monitor {
    pub x: f64,
    pub y: f64,
    pub width: f64,
    pub height: f64,
    pub color: Color,
    pub screen_color: Color,
}

impl Monitor {
    pub fn new(x: f64, y: f64) -> Self {
        Self {
            x,
            y,
            width: 30.0,
            height: 15.0,
            color: Color::White,
            screen_color: Color::Black,
        }
    }
}

impl Shape for Monitor {
    fn draw(&self, painter: &mut Painter) {
        // Fill the screen area with horizontal lines
        let step = fill_step();
        let mut y = self.y;
        while y <= self.y + self.height {
            CanvasLine {
                x1: self.x,
                y1: y,
                x2: self.x + self.width,
                y2: y,
                color: self.screen_color,
            }.draw(painter);
            y += step;
        }

        // Screen bezel (outline)
        Rectangle {
            x: self.x,
            y: self.y,
            width: self.width,
            height: self.height,
            color: self.color,
        }.draw(painter);

        // Stand neck - filled with lines
        let neck_width = 0.2 * self.width;
        let neck_height = 0.13 * self.width;
        let neck_x = self.x + (self.width - neck_width) / 2.0;
        let mut y = self.y - neck_height;
        while y <= self.y {
            CanvasLine {
                x1: neck_x,
                y1: y,
                x2: neck_x + neck_width,
                y2: y,
                color: self.color,
            }.draw(painter);
            y += step;
        }

        // Stand base
        let base_width = self.width * 0.4;
        let base_x = self.x + (self.width - base_width) / 2.0;
        CanvasLine {
            x1: base_x,
            y1: self.y - neck_height,
            x2: base_x + base_width,
            y2: self.y - neck_height,
            color: self.color,
        }.draw(painter);
    }
}

/// A robot icon made of canvas primitives
///
/// ```text
///      ◯
///      █
///  ▟███████▙
///  ██ ███ ██
///  ▜███████▛
/// ```
#[derive(Clone)]
pub struct Robot {
    pub x: f64,
    pub y: f64,
    pub width: f64,
    pub height: f64,
    pub color: Color,
}

impl Robot {
    pub fn new(x: f64, y: f64) -> Self {
        Self {
            x,
            y,
            width: 27.0,
            height: 27.0,
            color: Color::Magenta,
        }
    }
}

impl Shape for Robot {
    fn draw(&self, painter: &mut Painter) {
        let step = fill_step();

        // Layout: body takes 60%, antenna 25%, ball 15%
        let body_w = self.width;
        let body_h = self.height * 0.60;
        let body_x = self.x;
        let body_y = self.y;
        let fillet_r = body_h * 0.2;

        // Fill body with filleted corners
        // Draw horizontal scan lines, insetting at the top and bottom for rounded corners
        let mut y = body_y;
        while y <= body_y + body_h {
            let dy_bot = y - body_y;           // distance from bottom edge
            let dy_top = (body_y + body_h) - y; // distance from top edge

            // Calculate horizontal inset for fillet at corners
            let inset = if dy_bot < fillet_r {
                // Bottom corners
                let t = 1.0 - dy_bot / fillet_r;
                fillet_r * (1.0 - (1.0 - t * t).sqrt())
            } else if dy_top < fillet_r {
                // Top corners
                let t = 1.0 - dy_top / fillet_r;
                fillet_r * (1.0 - (1.0 - t * t).sqrt())
            } else {
                0.0
            };

            CanvasLine {
                x1: body_x + inset,
                y1: y,
                x2: body_x + body_w - inset,
                y2: y,
                color: self.color,
            }.draw(painter);
            y += step;
        }

        // Eyes - cut out two gaps in the body
        let eye_w = body_w * 0.15;
        let eye_h = body_h * 0.30;
        let eye_y = body_y + body_h * 0.35;
        let left_eye_x = body_x + body_w * 0.18;
        let right_eye_x = body_x + body_w * 0.67;

        let mut y = eye_y;
        while y <= eye_y + eye_h {
            CanvasLine {
                x1: left_eye_x,
                y1: y,
                x2: left_eye_x + eye_w,
                y2: y,
                color: Color::Black,
            }.draw(painter);
            CanvasLine {
                x1: right_eye_x,
                y1: y,
                x2: right_eye_x + eye_w,
                y2: y,
                color: Color::Black,
            }.draw(painter);
            y += step;
        }

        // Antenna neck - tall narrow column above body
        let neck_w = body_w * 0.035;
        let neck_h = self.height * 0.25;
        let neck_x = body_x + (body_w - neck_w) / 2.0;
        let neck_y = body_y + body_h;

        let mut y = neck_y;
        while y <= neck_y + neck_h {
            CanvasLine {
                x1: neck_x,
                y1: y,
                x2: neck_x + neck_w,
                y2: y,
                color: self.color,
            }.draw(painter);
            y += step;
        }

        // Antenna ball - filled circle at top
        // Terminal cells are ~2x tall as wide, so use separate x/y radii
        let ball_rx = self.height * 0.12; // horizontal radius in canvas units
        let ball_ry = ball_rx * 0.7;      // vertical radius scaled to appear round
        let ball_cx = body_x + body_w / 2.0;
        let ball_cy = neck_y + neck_h + ball_ry;

        // Fill with horizontal scan lines using ellipse math
        let mut dy = -ball_ry;
        while dy <= ball_ry {
            let t = dy / ball_ry;
            let half_w = ball_rx * (1.0 - t * t).sqrt();
            CanvasLine {
                x1: ball_cx - half_w,
                y1: ball_cy + dy,
                x2: ball_cx + half_w,
                y2: ball_cy + dy,
                color: self.color,
            }.draw(painter);
            dy += step;
        }
    }
}

/// A three-unit rack server icon
///
/// ```text
/// ┌──────────────┐
/// │ ●  ═══════   │
/// ├──────────────┤
/// │ ●  ═══════   │
/// ├──────────────┤
/// │ ●  ═══════   │
/// └──────────────┘
/// ```
#[derive(Clone)]
pub struct Server {
    pub x: f64,
    pub y: f64,
    pub width: f64,
    pub height: f64,
    pub color: Color,
}

impl Server {
    pub fn new(x: f64, y: f64) -> Self {
        Self {
            x,
            y,
            width: 30.0,
            height: 24.0,
            color: Color::White,
        }
    }
}

impl Shape for Server {
    fn draw(&self, painter: &mut Painter) {
        let step = fill_step();
        let unit_h = self.height / 3.0;

        for i in 0..3 {
            let uy = self.y + i as f64 * unit_h;

            // Fill unit background
            let mut y = uy;
            while y <= uy + unit_h {
                CanvasLine {
                    x1: self.x,
                    y1: y,
                    x2: self.x + self.width,
                    y2: y,
                    color: Color::Black,
                }.draw(painter);
                y += step;
            }

            // Unit outline
            Rectangle {
                x: self.x,
                y: uy,
                width: self.width,
                height: unit_h,
                color: self.color,
            }.draw(painter);

            // Status LED - small filled square on the left
            let led_size = unit_h * 0.25;
            let led_x = self.x + self.width * 0.08;
            let led_cy = uy + unit_h * 0.5;
            let mut y = led_cy - led_size * 0.5;
            while y <= led_cy + led_size * 0.5 {
                CanvasLine {
                    x1: led_x,
                    y1: y,
                    x2: led_x + led_size,
                    y2: y,
                    color: self.color,
                }.draw(painter);
                y += step;
            }

            // Drive bay lines - horizontal bars in the middle
            let bar_x = self.x + self.width * 0.25;
            let bar_w = self.width * 0.55;
            let bar_cy = uy + unit_h * 0.5;
            CanvasLine {
                x1: bar_x,
                y1: bar_cy,
                x2: bar_x + bar_w,
                y2: bar_cy,
                color: self.color,
            }.draw(painter);
        }
    }
}

/// A simple circle shape
#[derive(Clone)]
pub struct Circle {
    pub x: f64,
    pub y: f64,
    pub radius: f64,
    pub color: Color,
}

impl Circle {
    pub fn new(x: f64, y: f64, radius: f64) -> Self {
        Self {
            x,
            y,
            radius,
            color: Color::White,
        }
    }
}

impl Shape for Circle {
    fn draw(&self, painter: &mut Painter) {
        CanvasCircle {
            x: self.x,
            y: self.y,
            radius: self.radius,
            color: self.color,
        }.draw(painter);
    }
}

/// A simple filled rectangle for task nodes in playbook visualizations
#[derive(Clone)]
pub struct Node {
    /// Left edge in canvas coordinates
    pub x: f64,
    /// Bottom edge in canvas coordinates
    pub y: f64,
    pub width: f64,
    pub height: f64,
    /// Border color
    pub color: Color,
}

impl Node {
    pub fn new(x: f64, y: f64, width: f64, height: f64) -> Self {
        Self { x, y, width, height, color: Color::White }
    }

    pub fn with_color(mut self, color: Color) -> Self {
        self.color = color;
        self
    }
}

impl Shape for Node {
    fn draw(&self, painter: &mut Painter) {
        let step = fill_step();
        // Fill interior with shape color (occludes connector lines behind the node)
        let mut y = self.y + step;
        while y < self.y + self.height {
            CanvasLine {
                x1: self.x + step,
                y1: y,
                x2: self.x + self.width - step,
                y2: y,
                color: self.color,
            }.draw(painter);
            y += step;
        }
        // Draw border (same color as fill)
        Rectangle {
            x: self.x,
            y: self.y,
            width: self.width,
            height: self.height,
            color: self.color,
        }.draw(painter);
    }
}
