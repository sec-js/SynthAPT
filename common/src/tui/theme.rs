//! Nord color theme
//! https://www.nordtheme.com/

use ratatui::style::Color;

// Polar Night (dark)
pub const BG: Color = Color::Rgb(46, 52, 64);         // #2E3440
pub const BLACK: Color = Color::Rgb(59, 66, 82);      // #3B4252
pub const BRIGHT_BLACK: Color = Color::Rgb(76, 86, 106); // #4C566A
pub const SELECTION: Color = Color::Rgb(67, 76, 94);  // #434C5E

// Snow Storm (light)
pub const FG: Color = Color::Rgb(216, 222, 233);      // #D8DEE9
pub const WHITE: Color = Color::Rgb(229, 233, 240);   // #E5E9F0
pub const BRIGHT_WHITE: Color = Color::Rgb(236, 239, 244); // #ECEFF4

// Frost (blue/cyan)
pub const CYAN: Color = Color::Rgb(136, 192, 208);    // #88C0D0
pub const BRIGHT_CYAN: Color = Color::Rgb(143, 188, 187); // #8FBCBB
pub const BLUE: Color = Color::Rgb(129, 161, 193);    // #81A1C1
pub const DARK_BLUE: Color = Color::Rgb(94, 129, 172);    // #81A1C1

// Aurora (accent colors)
pub const RED: Color = Color::Rgb(191, 97, 106);      // #BF616A
pub const GREEN: Color = Color::Rgb(163, 190, 140);   // #A3BE8C
pub const YELLOW: Color = Color::Rgb(235, 203, 139);  // #EBCB8B
pub const ORANGE: Color = Color::Rgb(208, 135, 112);  // #EBCB8B
pub const PURPLE: Color = Color::Rgb(180, 142, 173);  // #B48EAD
pub const MAGENTA: Color = PURPLE;

// Aliases for convenience
pub const DARK_GRAY: Color = BRIGHT_BLACK;
pub const GRAY: Color = Color::Rgb(100, 110, 130);    // midpoint
