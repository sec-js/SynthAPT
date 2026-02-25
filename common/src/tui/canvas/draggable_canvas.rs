// Some methods kept for future use (pan, render, render_layered)
#![allow(dead_code)]

use std::collections::BTreeMap;

use ratatui::{
    buffer::Buffer,
    crossterm::event::{self, MouseButton, MouseEventKind},
    layout::{Alignment, Rect},
    symbols::Marker,
    text::Span,
    widgets::{
        canvas::{Canvas, Context},
        Block, Paragraph, Widget,
    },
    Frame,
};
use ratatui::style::{Color, Style};
use super::shapes::{Connector, LayeredShape, PinnedIndicators};

/// A draggable and zoomable canvas that can render any content.
/// Handles panning via mouse drag and zooming via scroll wheel.
pub struct DraggableCanvas {
    /// Center X coordinate in canvas space
    pub center_x: f64,
    /// Center Y coordinate in canvas space
    pub center_y: f64,
    /// Zoom level (higher = more zoomed in)
    pub zoom: f64,
    /// Base width of the canvas coordinate system
    pub base_width: f64,
    /// Base height of the canvas coordinate system
    pub base_height: f64,
    /// Minimum zoom level
    pub min_zoom: f64,
    /// Maximum zoom level
    pub max_zoom: f64,
    /// Zoom factor per scroll step
    pub zoom_factor: f64,
    /// Layer markers: layer number -> marker type (lower layers render first)
    pub layers: BTreeMap<u8, Marker>,

    // Internal dragging state
    is_dragging: bool,
    drag_start_x: u16,
    drag_start_y: u16,
    drag_start_center_x: f64,
    drag_start_center_y: f64,
    last_area_x: u16,
    last_area_y: u16,
    last_area_width: u16,
    last_area_height: u16,
}

impl Default for DraggableCanvas {
    fn default() -> Self {
        Self {
            center_x: 0.0,
            center_y: 0.0,
            zoom: 1.0,
            base_width: 200.0,
            base_height: 100.0,
            min_zoom: 0.1,
            max_zoom: 100.0,
            zoom_factor: 1.2,
            layers: BTreeMap::new(),
            is_dragging: false,
            drag_start_x: 0,
            drag_start_y: 0,
            drag_start_center_x: 0.0,
            drag_start_center_y: 0.0,
            last_area_x: 0,
            last_area_y: 0,
            last_area_width: 80,
            last_area_height: 24,
        }
    }
}

impl DraggableCanvas {
    /// Create a new draggable canvas with the given coordinate bounds.
    /// The canvas will show content from -width/2 to +width/2 on x-axis
    /// and -height/2 to +height/2 on y-axis at zoom level 1.0.
    pub fn new(base_width: f64, base_height: f64) -> Self {
        Self {
            base_width,
            base_height,
            ..Default::default()
        }
    }

    /// Convert screen coordinates (terminal col, row) to canvas coordinates
    pub fn screen_to_canvas(&self, col: u16, row: u16) -> (f64, f64) {
        let (x_min, x_max, y_min, y_max) = self.get_bounds();
        let rel_col = col.saturating_sub(self.last_area_x) as f64;
        let rel_row = row.saturating_sub(self.last_area_y) as f64;
        let x = x_min + (rel_col / self.last_area_width as f64) * (x_max - x_min);
        // Y is inverted: row 0 is top of screen but max Y in canvas
        let y = y_max - (rel_row / self.last_area_height as f64) * (y_max - y_min);
        (x, y)
    }

    /// Convert canvas coordinates to screen coordinates (col, row)
    pub fn canvas_to_screen(&self, x: f64, y: f64) -> (u16, u16) {
        let (x_min, x_max, y_min, y_max) = self.get_bounds();
        let col = ((x - x_min) / (x_max - x_min) * self.last_area_width as f64) as u16;
        // Y is inverted
        let row = ((y_max - y) / (y_max - y_min) * self.last_area_height as f64) as u16;
        (col, row)
    }

    /// Get the visible bounds (x_min, x_max, y_min, y_max) based on center, zoom, and terminal size.
    /// Maintains consistent aspect ratio regardless of terminal dimensions.
    pub fn get_bounds(&self) -> (f64, f64, f64, f64) {
        // Terminal characters are ~2x taller than wide
        let char_aspect = 2.0;

        // Calculate the terminal's aspect ratio in "square" units
        let term_width = self.last_area_width as f64;
        let term_height = self.last_area_height as f64 * char_aspect;

        // Use a fixed scale: 1 canvas unit = consistent size regardless of terminal
        let pixels_per_unit = term_width.min(term_height) / (self.base_width.min(self.base_height) / self.zoom);

        let view_width = term_width / pixels_per_unit;
        let view_height = term_height / pixels_per_unit;

        let x_min = self.center_x - view_width / 2.0;
        let x_max = self.center_x + view_width / 2.0;
        let y_min = self.center_y - view_height / 2.0;
        let y_max = self.center_y + view_height / 2.0;

        (x_min, x_max, y_min, y_max)
    }

    /// Handle a mouse event. Returns true if the event was consumed.
    pub fn handle_mouse_event(&mut self, event: event::MouseEvent) -> bool {
        match event.kind {
            MouseEventKind::Down(MouseButton::Left) => {
                self.is_dragging = true;
                self.drag_start_x = event.column;
                self.drag_start_y = event.row;
                self.drag_start_center_x = self.center_x;
                self.drag_start_center_y = self.center_y;
                true
            }
            MouseEventKind::Up(MouseButton::Left) => {
                self.is_dragging = false;
                true
            }
            MouseEventKind::Drag(MouseButton::Left) => {
                if self.is_dragging {
                    let (x_min, x_max, y_min, y_max) = self.get_bounds();
                    let map_width = x_max - x_min;
                    let map_height = y_max - y_min;

                    let dx = event.column as i32 - self.drag_start_x as i32;
                    let dy = event.row as i32 - self.drag_start_y as i32;

                    // Terminal characters are roughly 2x taller than wide
                    let map_dx = -(dx as f64) * map_width / self.last_area_width as f64;
                    let map_dy = (dy as f64) * map_height / self.last_area_height as f64 * 2.0;

                    self.center_x = self.drag_start_center_x + map_dx;
                    self.center_y = self.drag_start_center_y + map_dy;
                    true
                } else {
                    false
                }
            }
            MouseEventKind::ScrollUp => {
                self.zoom_in();
                true
            }
            MouseEventKind::ScrollDown => {
                self.zoom_out();
                true
            }
            _ => false,
        }
    }

    /// Zoom in by the zoom factor
    pub fn zoom_in(&mut self) {
        self.zoom = (self.zoom * self.zoom_factor).min(self.max_zoom);
    }

    /// Zoom out by the zoom factor
    pub fn zoom_out(&mut self) {
        self.zoom = (self.zoom / self.zoom_factor).max(self.min_zoom);
    }

    /// Pan the canvas by the given amount in canvas coordinates
    pub fn pan(&mut self, dx: f64, dy: f64) {
        self.center_x += dx;
        self.center_y += dy;
    }

    /// Pan by a fixed amount adjusted for current zoom level
    pub fn pan_scaled(&mut self, dx: f64, dy: f64) {
        let scale = 20.0 / self.zoom;
        self.center_x += dx * scale;
        self.center_y += dy * scale;
    }

    /// Reset to the default view (centered at origin, zoom 1.0)
    pub fn reset_view(&mut self) {
        self.center_x = 0.0;
        self.center_y = 0.0;
        self.zoom = 1.0;
    }

    /// Render the canvas with a custom paint function.
    /// The paint function receives a Context to draw on.
    pub fn render<F>(&mut self, frame: &mut Frame, area: Rect, block: Block, marker: Marker, paint: F)
    where
        F: Fn(&mut Context),
    {
        self.last_area_x = area.x;
        self.last_area_y = area.y;
        self.last_area_width = area.width;
        self.last_area_height = area.height;

        let (x_min, x_max, y_min, y_max) = self.get_bounds();

        let canvas = Canvas::default()
            .block(block)
            .marker(marker)
            .x_bounds([x_min, x_max])
            .y_bounds([y_min, y_max])
            .paint(paint);

        frame.render_widget(canvas, area);
    }

    /// Set the marker for a specific layer
    pub fn set_layer_marker(&mut self, layer: u8, marker: Marker) {
        self.layers.insert(layer, marker);
    }

    /// Render layered shapes and connectors. Connectors render on layer 0,
    /// then shapes render on their assigned layers.
    pub fn render_layered(
        &mut self,
        frame: &mut Frame,
        area: Rect,
        block: Block,
        shapes: &[LayeredShape],
        connectors: &[Connector],
    ) {
        self.render_layered_with_indicators(frame, area, block, shapes, connectors, &[]);
    }

    /// Render layered shapes, connectors, and pinned indicators.
    pub fn render_layered_with_indicators(
        &mut self,
        frame: &mut Frame,
        area: Rect,
        block: Block,
        shapes: &[LayeredShape],
        connectors: &[Connector],
        pinned_indicators: &[&PinnedIndicators],
    ) {
        self.last_area_x = area.x;
        self.last_area_y = area.y;
        self.last_area_width = area.width;
        self.last_area_height = area.height;

        let (x_min, x_max, y_min, y_max) = self.get_bounds();

        // Compute optimal fill step based on viewport resolution.
        if area.height > 0 {
            let canvas_height = (y_max - y_min).abs();
            let sub_pixels = area.height as f64 * 2.0; // HalfBlock = 2 rows per cell
            let pixel_step = canvas_height / sub_pixels;
            super::shapes::set_fill_step(pixel_step.clamp(0.1, 1.0));
        }

        // ── Single pass over shapes: collect centers, bounds, visible layers, labels ──
        let mut shape_centers = Vec::with_capacity(shapes.len());
        let mut shape_bounds_list = Vec::with_capacity(shapes.len());
        // Groups of shapes sharing the same marker: (marker, shapes)
        let mut marker_groups: Vec<(Marker, Vec<&LayeredShape>)> = Vec::new();
        let mut all_labels: Vec<(f64, f64, ratatui::text::Text<'static>)> = Vec::new();

        let connector_marker = self.layers.get(&0).copied().unwrap_or(Marker::Braille);

        for shape in shapes {
            let center = shape.shape.center();
            let bounds = shape.shape.bounds();
            shape_centers.push((shape.id, center));
            shape_bounds_list.push((shape.id, bounds));

            // Viewport cull
            let (bx, by, bw, bh) = bounds;
            if bx + bw < x_min || bx > x_max || by + bh < y_min || by > y_max {
                continue;
            }

            // Group by marker
            let marker = self.layers.get(&shape.layer).copied().unwrap_or(Marker::Braille);
            let disc = std::mem::discriminant(&marker);
            if let Some(group) = marker_groups.iter_mut().find(|(m, _)| std::mem::discriminant(m) == disc) {
                group.1.push(shape);
            } else {
                marker_groups.push((marker, vec![shape]));
            }

            // Collect labels inline
            if let Some(label) = &shape.label {
                let (lx, ly) = shape.shape.label_position(label.position);
                all_labels.push((lx, ly, label.text.clone()));
            }
        }

        // Build center lookup for connectors
        let center_map: std::collections::HashMap<_, _> = shape_centers.iter().copied().collect();

        // Collect connector line segments
        let connector_lines: Vec<_> = connectors
            .iter()
            .filter_map(|c| {
                let from = center_map.get(&c.from)?;
                let to = center_map.get(&c.to)?;
                let dx = to.0 - from.0;
                let dy = to.1 - from.1;
                Some(c.get_segments().into_iter().map(move |(sp, ep)| {
                    (from.0 + dx * sp, from.1 + dy * sp, from.0 + dx * ep, from.1 + dy * ep, c.color)
                }))
            })
            .flatten()
            .collect();

        // ── Render pass 1: connector marker group (with block/border) ──
        let connector_disc = std::mem::discriminant(&connector_marker);
        let connector_group_idx = marker_groups.iter().position(|(m, _)| std::mem::discriminant(m) == connector_disc);
        let connector_group_shapes: Vec<&LayeredShape> = connector_group_idx
            .map(|i| marker_groups.remove(i).1)
            .unwrap_or_default();

        let canvas = Canvas::default()
            .block(block)
            .marker(connector_marker)
            .x_bounds([x_min, x_max])
            .y_bounds([y_min, y_max])
            .paint(|ctx| {
                for &(x1, y1, x2, y2, color) in &connector_lines {
                    ctx.draw(&ratatui::widgets::canvas::Line { x1, y1, x2, y2, color });
                }
                for s in &connector_group_shapes {
                    ctx.draw(&s.shape);
                }
            });
        frame.render_widget(canvas, area);

        // ── Render pass 2+: remaining marker groups (merged via temp buffer) ──
        for (marker, group_shapes) in marker_groups {
            let canvas = Canvas::default()
                .marker(marker)
                .x_bounds([x_min, x_max])
                .y_bounds([y_min, y_max])
                .paint(|ctx| {
                    for s in &group_shapes {
                        ctx.draw(&s.shape);
                    }
                });

            let mut temp_buf = Buffer::empty(area);
            canvas.render(area, &mut temp_buf);

            let frame_buf = frame.buffer_mut();
            for y in area.top()..area.bottom() {
                for x in area.left()..area.right() {
                    let cell = temp_buf.cell((x, y)).unwrap();
                    if cell.symbol() != " " && cell.symbol() != "" {
                        if let Some(frame_cell) = frame_buf.cell_mut((x, y)) {
                            *frame_cell = cell.clone();
                        }
                    }
                }
            }
        }

        // ── Labels ──
        for (cx, cy, text) in all_labels {
            let (col, row) = self.canvas_to_screen(cx, cy);
            let text_w = text.width() as u16;
            let text_h = text.height() as u16;
            let start_col = col.saturating_sub(text_w / 2);
            let start_row = row.saturating_sub(text_h / 2);

            if start_row < area.height && start_col < area.width {
                let label_area = Rect::new(
                    area.x + start_col,
                    area.y + start_row,
                    text_w.min(area.width.saturating_sub(start_col)),
                    text_h.min(area.height.saturating_sub(start_row)),
                );
                let para = Paragraph::new(text).alignment(Alignment::Center);
                frame.render_widget(para, label_area);
            }
        }

        // ── Pinned indicators ──
        let bounds_map: std::collections::HashMap<_, _> = shape_bounds_list.into_iter().collect();
        for indicators in pinned_indicators {
            if let Some(&bounds) = bounds_map.get(&indicators.parent_id) {
                for (cx, cy, text, color) in indicators.calculate_positions(bounds) {
                    let (col, row) = self.canvas_to_screen(cx, cy);
                    let text_len = text.len() as u16;

                    if row < area.height && col < area.width {
                        let indicator_area = Rect::new(
                            area.x + col,
                            area.y + row,
                            text_len.min(area.width - col),
                            1,
                        );
                        let para = Paragraph::new(Span::styled(
                            text,
                            ratatui::style::Style::default().fg(color),
                        ));
                        frame.render_widget(para, indicator_area);
                    }
                }
            }
        }

        // ── Entrance glitch pass ──
        for shape in shapes {
            let Some(entrance) = &shape.entrance else { continue };
            let progress = entrance.progress();
            if progress >= 1.0 {
                continue;
            }

            let (bx, by, bw, bh) = shape.shape.bounds();
            let (scr_left, scr_top) = self.canvas_to_screen(bx, by + bh);
            let (scr_right, scr_bottom) = self.canvas_to_screen(bx + bw, by);

            let margin = ((1.0 - progress) * 3.0) as u16;
            let min_col = (area.x + scr_left).saturating_sub(margin).max(area.x);
            let max_col = (area.x + scr_right + margin + 1).min(area.x + area.width);
            let min_row = (area.y + scr_top).saturating_sub(margin).max(area.y);
            let max_row = (area.y + scr_bottom + margin + 1).min(area.y + area.height);

            let glitch_area = Rect {
                x: min_col,
                y: min_row,
                width: max_col.saturating_sub(min_col),
                height: max_row.saturating_sub(min_row),
            };

            apply_entrance_glitch(frame.buffer_mut(), glitch_area, progress, entrance.seed);
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Entrance glitch effect
// ═══════════════════════════════════════════════════════════════════════════════

const GLITCH_CHARS: &[char] = &['░', '▒', '▓', '█', '▄', '▀', '▐', '▌', '╌', '┄', '╍', '┅'];

/// Simple hash for deterministic pseudo-random per-cell values
fn glitch_hash(seed: u64, a: u64, b: u64) -> u64 {
    let mut h = seed;
    h = h.wrapping_mul(6364136223846793005).wrapping_add(a);
    h = h.wrapping_mul(6364136223846793005).wrapping_add(b);
    h ^= h >> 33;
    h = h.wrapping_mul(0xff51afd7ed558ccd);
    h ^= h >> 33;
    h
}

/// Apply entrance glitch/coalesce effect to a region of the buffer.
/// At progress=0 the region is mostly noise; at progress=1 it's untouched.
fn apply_entrance_glitch(buf: &mut Buffer, area: Rect, progress: f64, seed: u64) {
    // Ease-out: fast initial reveal, slow final settle
    let ease = 1.0 - (1.0 - progress).powi(3);

    // Per-frame time component for flickering (changes every ~50ms)
    let time_phase = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64 / 16;
    let frame_seed = seed ^ time_phase;

    for y in area.top()..area.bottom() {
        // Horizontal displacement for this row (CRT scanline glitch)
        let row_hash = glitch_hash(frame_seed, y as u64, 0xDEAD);
        let max_disp = ((1.0 - ease) * 4.0) as i16;
        let displacement = if max_disp > 0 && row_hash % 4 == 0 {
            ((row_hash >> 8) as i16 % (max_disp * 2 + 1)) - max_disp
        } else {
            0
        };

        for x in area.left()..area.right() {
            let cell_hash = glitch_hash(frame_seed, y as u64, x as u64);
            let cell_rand = (cell_hash & 0xFFFF) as f64 / 65535.0;

            // Probability of glitching this cell (decreases with progress)
            let glitch_prob = (1.0 - ease) * 0.85;

            if cell_rand < glitch_prob {
                let Some(cell) = buf.cell_mut((x, y)) else { continue };

                if cell_rand < glitch_prob * 0.6 {
                    // Replace with glitch character
                    let char_idx = (cell_hash >> 16) as usize % GLITCH_CHARS.len();
                    cell.set_char(GLITCH_CHARS[char_idx]);

                    // Glitch color
                    let color = match (cell_hash >> 24) % 7 {
                        0 => Color::Cyan,
                        1 => Color::Magenta,
                        2 => Color::White,
                        3 => Color::Green,
                        4 => Color::DarkGray,
                        5 => Color::Blue,
                        _ => Color::LightCyan,
                    };
                    cell.set_style(Style::default().fg(color));
                } else if displacement != 0 {
                    // Horizontal shift: blank this cell (content "moved" sideways)
                    let src_x = (x as i16 + displacement).clamp(area.left() as i16, area.right() as i16 - 1) as u16;
                    if let Some(src_cell) = buf.cell((src_x, y)).cloned() {
                        if let Some(cell) = buf.cell_mut((x, y)) {
                            *cell = src_cell;
                        }
                    }
                } else {
                    // Blank out (creates gaps that fill in as animation progresses)
                    cell.set_char(' ');
                }
            }
        }
    }
}
