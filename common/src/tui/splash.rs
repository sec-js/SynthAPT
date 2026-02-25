//! Particle splash screen animation

use std::time::{Duration, Instant};
use ratatui::{
    buffer::Buffer,
    crossterm::event::{self, Event},
    layout::Rect,
    style::{Color, Modifier, Style},
    widgets::Widget,
    DefaultTerminal,
};

/// A character particle that will animate into place
struct Particle {
    char: char,
    final_x: f64,
    final_y: f64,
    current_x: f64,
    current_y: f64,
    angle: f64,
    radius: f64,
    delay: f64,
    color: Color,
}

pub struct SplashScreen {
    particles: Vec<Particle>,
    start_time: Instant,
    duration: Duration,
    logo_width: usize,
    logo_height: usize,
    subtitle: String,
    /// Target RGB components for the logo color, used for fade-in animation
    logo_rgb: (u8, u8, u8),
    last_glitch: Instant,
    glitch_active: bool,
    glitch_seed: u64,
    glitch_duration: f64,
}

impl SplashScreen {
    pub fn new(duration: Duration, logo: &str, subtitle: impl Into<String>, logo_color: Color) -> Self {
        let logo_rgb = color_to_rgb(logo_color);
        let mut particles = Vec::new();
        let lines: Vec<&str> = logo.lines().collect();
        let logo_height = lines.len();
        let logo_width = lines.iter().map(|l| l.chars().count()).max().unwrap_or(0);

        let mut rng_state: u64 = 12345;
        for (y, line) in lines.iter().enumerate() {
            for (x, ch) in line.chars().enumerate() {
                if ch != ' ' {
                    rng_state = rng_state.wrapping_mul(1103515245).wrapping_add(12345);
                    let rand1 = ((rng_state >> 16) & 0xFFFF) as f64 / 65536.0;
                    rng_state = rng_state.wrapping_mul(1103515245).wrapping_add(12345);
                    let rand2 = ((rng_state >> 16) & 0xFFFF) as f64 / 65536.0;
                    rng_state = rng_state.wrapping_mul(1103515245).wrapping_add(12345);
                    let rand3 = ((rng_state >> 16) & 0xFFFF) as f64 / 65536.0;

                    let angle = rand1 * std::f64::consts::TAU;
                    let radius = 15.0 + rand2 * 25.0;
                    let delay = rand3 * 0.3;

                    particles.push(Particle {
                        char: ch,
                        final_x: x as f64,
                        final_y: y as f64,
                        current_x: x as f64,
                        current_y: y as f64,
                        angle,
                        radius,
                        delay,
                        color: logo_color,
                    });
                }
            }
        }

        Self {
            particles,
            start_time: Instant::now(),
            duration,
            logo_width,
            logo_height,
            subtitle: subtitle.into(),
            logo_rgb,
            last_glitch: Instant::now(),
            glitch_active: false,
            glitch_seed: 0,
            glitch_duration: 0.1,
        }
    }

    fn update(&mut self) {
        let elapsed = self.start_time.elapsed().as_secs_f64();
        let total_duration = self.duration.as_secs_f64();
        let animation_duration = total_duration * 0.7;
        let animation_done = elapsed >= total_duration;

        if animation_done {
            let since_glitch = self.last_glitch.elapsed().as_secs_f64();
            if self.glitch_active {
                if since_glitch > self.glitch_duration {
                    self.glitch_active = false;
                    self.last_glitch = Instant::now();
                }
            } else {
                let time_hash = (elapsed * 1000.0) as u64;
                if since_glitch > 2.0 && (time_hash % 60 == 0) {
                    self.glitch_active = true;
                    self.glitch_seed = time_hash;
                    self.glitch_duration = 0.1 + ((time_hash >> 4) & 0xFF) as f64 / 2550.0;
                    self.last_glitch = Instant::now();
                }
            }
        }

        let (lr, lg, lb) = self.logo_rgb;

        for (i, particle) in self.particles.iter_mut().enumerate() {
            let particle_elapsed = (elapsed - particle.delay).max(0.0);
            let t = (particle_elapsed / animation_duration).clamp(0.0, 1.0);
            let eased = 1.0 - (1.0 - t).powi(3);

            let current_radius = particle.radius * (1.0 - eased);
            let current_angle = particle.angle + (1.0 - eased) * std::f64::consts::TAU * 3.0;

            let mut offset_x = current_angle.cos() * current_radius;
            let mut offset_y = current_angle.sin() * current_radius * 0.5;

            if self.glitch_active {
                let glitch_hash = self.glitch_seed.wrapping_add(i as u64);
                if glitch_hash % 5 == 0 {
                    offset_x += ((glitch_hash >> 8) & 0xF) as f64 - 8.0;
                    offset_y += (((glitch_hash >> 12) & 0x7) as f64 - 4.0) * 0.3;
                }
            }

            particle.current_x = particle.final_x + offset_x;
            particle.current_y = particle.final_y + offset_y;

            if self.glitch_active {
                let glitch_hash = self.glitch_seed.wrapping_add(i as u64);
                if glitch_hash % 7 == 0 {
                    particle.color = if glitch_hash % 2 == 0 { Color::White } else { Color::Magenta };
                } else {
                    particle.color = Color::Rgb(lr, lg, lb);
                }
            } else {
                particle.color = Color::Rgb(lr, lg, lb);
            }
        }
    }

    pub fn is_done(&self) -> bool {
        self.start_time.elapsed() >= self.duration
    }
}

impl Widget for &SplashScreen {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let center_x = area.x as f64 + area.width as f64 / 2.0;
        let center_y = area.y as f64 + area.height as f64 / 2.0;
        let logo_offset_x = self.logo_width as f64 / 2.0;
        let logo_offset_y = self.logo_height as f64 / 2.0;

        let left = area.left() as f64;
        let right = area.right() as f64;
        let top = area.top() as f64;
        let bottom = area.bottom() as f64;

        for particle in &self.particles {
            let screen_x = center_x - logo_offset_x + particle.current_x;
            let screen_y = center_y - logo_offset_y + particle.current_y;

            if screen_x >= left && screen_x < right && screen_y >= top && screen_y < bottom {
                if let Some(cell) = buf.cell_mut((screen_x as u16, screen_y as u16)) {
                    cell.set_char(particle.char);
                    cell.set_style(Style::default().fg(particle.color));
                }
            }
        }

        let elapsed = self.start_time.elapsed().as_secs_f64();
        if elapsed > self.duration.as_secs_f64() * 0.8 {
            let sub_x = center_x - (self.subtitle.len() as f64 / 2.0);
            let sub_y = center_y + logo_offset_y + 2.0;

            if sub_y >= top && sub_y < bottom {
                for (i, ch) in self.subtitle.chars().enumerate() {
                    let x = sub_x + i as f64;
                    if x >= left && x < right {
                        if let Some(cell) = buf.cell_mut((x as u16, sub_y as u16)) {
                            cell.set_char(ch);
                            cell.set_style(
                                Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
                            );
                        }
                    }
                }
            }

            let hint = "Press any key to continue";
            let hint_x = center_x - (hint.len() as f64 / 2.0);
            let hint_y = sub_y + 2.0;

            if hint_y >= top && hint_y < bottom {
                for (i, ch) in hint.chars().enumerate() {
                    let x = hint_x + i as f64;
                    if x >= left && x < right {
                        if let Some(cell) = buf.cell_mut((x as u16, hint_y as u16)) {
                            cell.set_char(ch);
                            cell.set_style(Style::default().fg(Color::DarkGray));
                        }
                    }
                }
            }
        }
    }
}

/// Show the splash screen animation.
pub fn show_splash(
    terminal: &mut DefaultTerminal,
    logo: &str,
    subtitle: &str,
    logo_color: Color,
) -> std::io::Result<()> {
    let mut splash = SplashScreen::new(Duration::from_secs(3), logo, subtitle, logo_color);

    loop {
        splash.update();
        terminal.draw(|frame| frame.render_widget(&splash, frame.area()))?;

        if event::poll(Duration::from_millis(16))? {
            if let Event::Key(_) = event::read()? {
                break;
            }
        }
    }

    Ok(())
}

/// Convert a named Color to its approximate RGB components for animation.
fn color_to_rgb(color: Color) -> (u8, u8, u8) {
    match color {
        Color::Rgb(r, g, b) => (r, g, b),
        Color::Cyan => (0, 255, 255),
        Color::LightCyan => (128, 255, 255),
        Color::Green => (0, 255, 0),
        Color::LightGreen => (128, 255, 128),
        Color::Yellow => (255, 255, 0),
        Color::LightYellow => (255, 255, 128),
        Color::Blue => (0, 0, 255),
        Color::LightBlue => (128, 128, 255),
        Color::Magenta => (255, 0, 255),
        Color::LightMagenta => (255, 128, 255),
        Color::Red => (255, 0, 0),
        Color::LightRed => (255, 128, 128),
        Color::White => (255, 255, 255),
        Color::Gray => (128, 128, 128),
        _ => (0, 255, 255),
    }
}
