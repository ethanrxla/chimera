use ratatui::style::Color;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThemeName {
    Matrix,
    Red,
    Blue,
}

impl ThemeName {
    pub fn label(self) -> &'static str {
        match self {
            Self::Matrix => "MATRIX",
            Self::Red => "RED",
            Self::Blue => "BLUE",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "matrix" | "green" => Some(Self::Matrix),
            "red" | "ember" => Some(Self::Red),
            "blue" | "ice" => Some(Self::Blue),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Theme {
    pub panel_alt: Color,
    pub text: Color,
    pub muted: Color,
    pub accent: Color,
    pub accent_alt: Color,
    pub success: Color,
    pub danger: Color,
    pub highlight_fg: Color,
    pub highlight_bg: Color,
}

impl Theme {
    pub fn from_name(name: ThemeName) -> Self {
        match name {
            ThemeName::Matrix => Self {
                panel_alt: Color::Rgb(10, 18, 13),
                text: Color::Rgb(219, 245, 228),
                muted: Color::Rgb(110, 150, 122),
                accent: Color::Rgb(95, 235, 120),
                accent_alt: Color::Rgb(45, 196, 168),
                success: Color::Rgb(95, 235, 120),
                danger: Color::Rgb(255, 92, 92),
                highlight_fg: Color::Black,
                highlight_bg: Color::Rgb(95, 235, 120),
            },
            ThemeName::Red => Self {
                panel_alt: Color::Rgb(31, 13, 13),
                text: Color::Rgb(248, 228, 226),
                muted: Color::Rgb(160, 112, 108),
                accent: Color::Rgb(255, 88, 78),
                accent_alt: Color::Rgb(255, 159, 67),
                success: Color::Rgb(141, 235, 130),
                danger: Color::Rgb(255, 88, 78),
                highlight_fg: Color::Black,
                highlight_bg: Color::Rgb(255, 88, 78),
            },
            ThemeName::Blue => Self {
                panel_alt: Color::Rgb(10, 18, 30),
                text: Color::Rgb(225, 238, 250),
                muted: Color::Rgb(112, 140, 168),
                accent: Color::Rgb(94, 171, 255),
                accent_alt: Color::Rgb(110, 230, 233),
                success: Color::Rgb(102, 216, 151),
                danger: Color::Rgb(255, 107, 107),
                highlight_fg: Color::Black,
                highlight_bg: Color::Rgb(94, 171, 255),
            },
        }
    }
}
