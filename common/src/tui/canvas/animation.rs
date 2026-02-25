// Animation infrastructure - kept for future use
#![allow(dead_code)]

use std::time::{Duration, Instant};
use ratatui::style::Color;
use super::shapes::{LayeredShape, ShapeId, ShapeKind, Connector};

/// Easing functions for animations
#[derive(Clone, Copy, Default)]
pub enum Easing {
    #[default]
    Linear,
    EaseIn,
    EaseOut,
    EaseInOut,
}

impl Easing {
    /// Apply easing to a progress value (0.0 to 1.0)
    pub fn apply(&self, t: f64) -> f64 {
        match self {
            Easing::Linear => t,
            Easing::EaseIn => t * t,
            Easing::EaseOut => 1.0 - (1.0 - t) * (1.0 - t),
            Easing::EaseInOut => {
                if t < 0.5 {
                    2.0 * t * t
                } else {
                    1.0 - (-2.0 * t + 2.0).powi(2) / 2.0
                }
            }
        }
    }
}

/// What property to animate
#[derive(Clone)]
pub enum AnimationTarget {
    // Shape properties (by ShapeId)
    ShapeX(ShapeId),
    ShapeY(ShapeId),
    ShapeWidth(ShapeId),
    ShapeHeight(ShapeId),
    ShapeColor(ShapeId),

    // Monitor-specific
    MonitorScreenColor(ShapeId),

    // Connector properties (by index in connectors vec)
    ConnectorStartPercent(usize),
    ConnectorEndPercent(usize),
    ConnectorColor(usize),

    // Flow properties (by connector index)
    FlowSegmentLength(usize),
    FlowGap(usize),
    FlowSpeed(usize),
}

/// An animatable value that can be either f64 or Color
#[derive(Clone, Copy)]
pub enum AnimValue {
    Float(f64),
    Color(Color),
}

impl AnimValue {
    pub fn as_float(&self) -> f64 {
        match self {
            AnimValue::Float(f) => *f,
            AnimValue::Color(_) => 0.0,
        }
    }

    pub fn as_color(&self) -> Color {
        match self {
            AnimValue::Color(c) => *c,
            AnimValue::Float(_) => Color::White,
        }
    }

    /// Interpolate between two values
    pub fn lerp(from: AnimValue, to: AnimValue, t: f64) -> AnimValue {
        match (from, to) {
            (AnimValue::Float(a), AnimValue::Float(b)) => {
                AnimValue::Float(a + (b - a) * t)
            }
            (AnimValue::Color(a), AnimValue::Color(b)) => {
                AnimValue::Color(lerp_color(a, b, t))
            }
            _ => to, // mismatched types, just snap to target
        }
    }
}

/// Interpolate between two colors
pub fn lerp_color(from: Color, to: Color, t: f64) -> Color {
    // Extract RGB values (handle named colors by converting to RGB)
    let (r1, g1, b1) = color_to_rgb(from);
    let (r2, g2, b2) = color_to_rgb(to);

    let r = (r1 as f64 + (r2 as f64 - r1 as f64) * t) as u8;
    let g = (g1 as f64 + (g2 as f64 - g1 as f64) * t) as u8;
    let b = (b1 as f64 + (b2 as f64 - b1 as f64) * t) as u8;

    Color::Rgb(r, g, b)
}

/// Convert a Color to RGB values
pub fn color_to_rgb(color: Color) -> (u8, u8, u8) {
    match color {
        Color::Rgb(r, g, b) => (r, g, b),
        Color::Black => (0, 0, 0),
        Color::Red => (255, 0, 0),
        Color::Green => (0, 255, 0),
        Color::Yellow => (255, 255, 0),
        Color::Blue => (0, 0, 255),
        Color::Magenta => (255, 0, 255),
        Color::Cyan => (0, 255, 255),
        Color::White => (255, 255, 255),
        Color::Gray => (128, 128, 128),
        Color::DarkGray => (64, 64, 64),
        Color::LightRed => (255, 128, 128),
        Color::LightGreen => (128, 255, 128),
        Color::LightYellow => (255, 255, 128),
        Color::LightBlue => (128, 128, 255),
        Color::LightMagenta => (255, 128, 255),
        Color::LightCyan => (128, 255, 255),
        _ => (255, 255, 255), // default to white for indexed colors
    }
}

/// How an animation should repeat
#[derive(Clone, Copy, Default)]
pub enum Repeat {
    #[default]
    None,
    /// Loop N times
    Count(u32),
    /// Loop forever
    Forever,
    /// Ping-pong (reverse direction each cycle)
    PingPong,
    /// Ping-pong forever
    PingPongForever,
}

/// A single animation
#[derive(Clone)]
pub struct Animation {
    pub target: AnimationTarget,
    pub from: AnimValue,
    pub to: AnimValue,
    pub duration: Duration,
    pub easing: Easing,
    pub started_at: Instant,
    pub delay: Duration,
    pub repeat: Repeat,
    /// Current cycle count (for repeat modes)
    cycle: u32,
    /// Direction: true = forward, false = reverse (for ping-pong)
    forward: bool,
}

impl Animation {
    pub fn new(target: AnimationTarget, from: AnimValue, to: AnimValue, duration: Duration) -> Self {
        Self {
            target,
            from,
            to,
            duration,
            easing: Easing::default(),
            started_at: Instant::now(),
            delay: Duration::ZERO,
            repeat: Repeat::None,
            cycle: 0,
            forward: true,
        }
    }

    pub fn with_easing(mut self, easing: Easing) -> Self {
        self.easing = easing;
        self
    }

    pub fn with_delay(mut self, delay: Duration) -> Self {
        self.delay = delay;
        self
    }

    pub fn with_repeat(mut self, repeat: Repeat) -> Self {
        self.repeat = repeat;
        self
    }

    /// Convenience for infinite loop
    pub fn looping(mut self) -> Self {
        self.repeat = Repeat::Forever;
        self
    }

    /// Convenience for ping-pong forever
    pub fn ping_pong(mut self) -> Self {
        self.repeat = Repeat::PingPongForever;
        self
    }

    /// Get the current progress (0.0 to 1.0), accounting for delay and cycles
    pub fn progress(&self) -> f64 {
        let elapsed = self.started_at.elapsed();
        if elapsed < self.delay {
            return 0.0;
        }
        let active_elapsed = elapsed - self.delay;
        let cycle_duration = self.duration.as_secs_f64();
        let total_elapsed = active_elapsed.as_secs_f64();

        match self.repeat {
            Repeat::None => {
                // Non-repeating: clamp to 1.0 when done
                (total_elapsed / cycle_duration).clamp(0.0, 1.0)
            }
            _ => {
                // Repeating: use modulo for cycling
                let raw = (total_elapsed % cycle_duration) / cycle_duration;
                raw.clamp(0.0, 1.0)
            }
        }
    }

    /// Get the current cycle number
    fn current_cycle(&self) -> u32 {
        let elapsed = self.started_at.elapsed();
        if elapsed < self.delay {
            return 0;
        }
        let active_elapsed = elapsed - self.delay;
        (active_elapsed.as_secs_f64() / self.duration.as_secs_f64()) as u32
    }

    /// Check if the animation is complete
    pub fn is_complete(&self) -> bool {
        match self.repeat {
            Repeat::None => {
                let elapsed = self.started_at.elapsed();
                elapsed >= self.delay + self.duration
            }
            Repeat::Count(n) => self.current_cycle() >= n,
            Repeat::Forever | Repeat::PingPongForever => false,
            Repeat::PingPong => self.current_cycle() >= 2, // one forward, one back
        }
    }

    /// Get the current interpolated value
    pub fn current_value(&self) -> AnimValue {
        let progress = self.progress();

        // Handle ping-pong direction
        let effective_progress = match self.repeat {
            Repeat::PingPong | Repeat::PingPongForever => {
                let cycle = self.current_cycle();
                if cycle % 2 == 1 {
                    1.0 - progress // reverse
                } else {
                    progress
                }
            }
            _ => progress,
        };

        let t = self.easing.apply(effective_progress);
        AnimValue::lerp(self.from, self.to, t)
    }
}

/// Manages all active animations
#[derive(Default)]
pub struct Animator {
    animations: Vec<Animation>,
}

impl Animator {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an animation
    pub fn add(&mut self, animation: Animation) {
        self.animations.push(animation);
    }

    /// Convenience method to animate a float property
    pub fn animate_float(
        &mut self,
        target: AnimationTarget,
        from: f64,
        to: f64,
        duration: Duration,
    ) {
        self.add(Animation::new(
            target,
            AnimValue::Float(from),
            AnimValue::Float(to),
            duration,
        ));
    }

    /// Convenience method to animate a color property
    pub fn animate_color(
        &mut self,
        target: AnimationTarget,
        from: Color,
        to: Color,
        duration: Duration,
    ) {
        self.add(Animation::new(
            target,
            AnimValue::Color(from),
            AnimValue::Color(to),
            duration,
        ));
    }

    /// Check if there are any active animations
    pub fn is_animating(&self) -> bool {
        !self.animations.is_empty()
    }

    /// Tick all animations and apply to shapes/connectors
    /// Returns true if any animations are still active
    pub fn tick(&mut self, shapes: &mut [LayeredShape], connectors: &mut [Connector]) -> bool {
        // Apply all animations
        for anim in &self.animations {
            let value = anim.current_value();

            match &anim.target {
                AnimationTarget::ShapeX(id) => {
                    if let Some(shape) = find_shape_mut(shapes, *id) {
                        match &mut shape.shape {
                            ShapeKind::Monitor(m) => m.x = value.as_float(),
                            ShapeKind::Circle(c) => c.x = value.as_float(),
                            ShapeKind::Robot(r) => r.x = value.as_float(),
                            ShapeKind::Server(s) => s.x = value.as_float(),
                            ShapeKind::SelectionIndicator(si) => si.cx = value.as_float(),
                            ShapeKind::Node(n) => n.x = value.as_float(),
                        }
                    }
                }
                AnimationTarget::ShapeY(id) => {
                    if let Some(shape) = find_shape_mut(shapes, *id) {
                        match &mut shape.shape {
                            ShapeKind::Monitor(m) => m.y = value.as_float(),
                            ShapeKind::Circle(c) => c.y = value.as_float(),
                            ShapeKind::Robot(r) => r.y = value.as_float(),
                            ShapeKind::Server(s) => s.y = value.as_float(),
                            ShapeKind::SelectionIndicator(si) => si.cy = value.as_float(),
                            ShapeKind::Node(n) => n.y = value.as_float(),
                        }
                    }
                }
                AnimationTarget::ShapeWidth(id) => {
                    if let Some(shape) = find_shape_mut(shapes, *id) {
                        match &mut shape.shape {
                            ShapeKind::Monitor(m) => m.width = value.as_float(),
                            ShapeKind::Circle(c) => c.radius = value.as_float() / 2.0,
                            ShapeKind::Robot(r) => r.width = value.as_float(),
                            ShapeKind::Server(s) => s.width = value.as_float(),
                            ShapeKind::SelectionIndicator(si) => si.width = value.as_float(),
                            ShapeKind::Node(n) => n.width = value.as_float(),
                        }
                    }
                }
                AnimationTarget::ShapeHeight(id) => {
                    if let Some(shape) = find_shape_mut(shapes, *id) {
                        match &mut shape.shape {
                            ShapeKind::Monitor(m) => m.height = value.as_float(),
                            ShapeKind::Circle(c) => c.radius = value.as_float() / 2.0,
                            ShapeKind::Robot(r) => r.height = value.as_float(),
                            ShapeKind::Server(s) => s.height = value.as_float(),
                            ShapeKind::SelectionIndicator(si) => si.height = value.as_float(),
                            ShapeKind::Node(n) => n.height = value.as_float(),
                        }
                    }
                }
                AnimationTarget::ShapeColor(id) => {
                    if let Some(shape) = find_shape_mut(shapes, *id) {
                        match &mut shape.shape {
                            ShapeKind::Monitor(m) => m.color = value.as_color(),
                            ShapeKind::Circle(c) => c.color = value.as_color(),
                            ShapeKind::Robot(r) => r.color = value.as_color(),
                            ShapeKind::Server(s) => s.color = value.as_color(),
                            ShapeKind::SelectionIndicator(si) => si.color = value.as_color(),
                            ShapeKind::Node(n) => n.color = value.as_color(),
                        }
                    }
                }
                AnimationTarget::MonitorScreenColor(id) => {
                    if let Some(shape) = find_shape_mut(shapes, *id) {
                        match &mut shape.shape {
                            ShapeKind::Monitor(m) => m.screen_color = value.as_color(),
                            ShapeKind::Circle(_) | ShapeKind::Robot(_) | ShapeKind::Server(_)
                            | ShapeKind::SelectionIndicator(_) | ShapeKind::Node(_) => {}
                        }
                    }
                }
                AnimationTarget::ConnectorStartPercent(idx) => {
                    if let Some(conn) = connectors.get_mut(*idx) {
                        conn.start_percent = value.as_float();
                    }
                }
                AnimationTarget::ConnectorEndPercent(idx) => {
                    if let Some(conn) = connectors.get_mut(*idx) {
                        conn.end_percent = value.as_float();
                    }
                }
                AnimationTarget::ConnectorColor(idx) => {
                    if let Some(conn) = connectors.get_mut(*idx) {
                        conn.color = value.as_color();
                    }
                }
                AnimationTarget::FlowSegmentLength(idx) => {
                    if let Some(conn) = connectors.get_mut(*idx) {
                        if let Some(flow) = &mut conn.flow {
                            flow.segment_length = value.as_float();
                        }
                    }
                }
                AnimationTarget::FlowGap(idx) => {
                    if let Some(conn) = connectors.get_mut(*idx) {
                        if let Some(flow) = &mut conn.flow {
                            flow.gap = value.as_float();
                        }
                    }
                }
                AnimationTarget::FlowSpeed(idx) => {
                    if let Some(conn) = connectors.get_mut(*idx) {
                        if let Some(flow) = &mut conn.flow {
                            flow.speed = value.as_float();
                        }
                    }
                }
            }
        }

        // Remove completed animations
        self.animations.retain(|a| !a.is_complete());

        self.is_animating()
    }

    /// Cancel all animations for a specific shape
    pub fn cancel_for_shape(&mut self, id: ShapeId) {
        self.animations.retain(|a| {
            !matches!(
                &a.target,
                AnimationTarget::ShapeX(i) |
                AnimationTarget::ShapeY(i) |
                AnimationTarget::ShapeWidth(i) |
                AnimationTarget::ShapeHeight(i) |
                AnimationTarget::ShapeColor(i) |
                AnimationTarget::MonitorScreenColor(i)
                if *i == id
            )
        });
    }

    /// Cancel all animations
    pub fn cancel_all(&mut self) {
        self.animations.clear();
    }
}

fn find_shape_mut(shapes: &mut [LayeredShape], id: ShapeId) -> Option<&mut LayeredShape> {
    shapes.iter_mut().find(|s| s.id == id)
}
