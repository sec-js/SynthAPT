use std::path::PathBuf;

/// Application configuration stored at ~/.config/SynthAPT/config.toml
#[derive(Debug, Clone, Default)]
pub struct Config {
    pub api_key: Option<String>,
}

#[derive(Debug)]
pub enum ConfigError {
    Io(String),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigError::Io(msg) => write!(f, "IO error: {}", msg),
        }
    }
}

impl Config {
    /// ~/.config/SynthAPT/
    pub fn config_dir() -> Option<PathBuf> {
        dirs::config_dir().map(|p| p.join("SynthAPT"))
    }

    /// ~/.config/SynthAPT/config.toml
    pub fn config_path() -> Option<PathBuf> {
        Self::config_dir().map(|p| p.join("config.toml"))
    }

    /// Returns true when the config file is absent (first-run wizard needed).
    pub fn needs_setup() -> bool {
        !Self::config_path()
            .map(|p| p.exists())
            .unwrap_or(false)
    }

    /// Load config from disk, returning defaults if the file is missing or unreadable.
    pub fn load() -> Self {
        let path = match Self::config_path() {
            Some(p) if p.exists() => p,
            _ => return Self::default(),
        };
        let content = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(_) => return Self::default(),
        };
        Self::parse_toml(&content)
    }

    /// Persist config to disk, creating the directory if needed.
    pub fn save(&self) -> Result<(), ConfigError> {
        let path = Self::config_path()
            .ok_or_else(|| ConfigError::Io("cannot determine config path".to_string()))?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| ConfigError::Io(e.to_string()))?;
        }
        std::fs::write(&path, self.to_toml())
            .map_err(|e| ConfigError::Io(e.to_string()))
    }

    fn to_toml(&self) -> String {
        let mut lines = vec!["[claude]".to_string()];
        match &self.api_key {
            Some(key) => lines.push(format!("api_key = \"{}\"", key)),
            None => lines.push("# api_key = \"sk-ant-...\"".to_string()),
        }
        lines.push(String::new());
        lines.join("\n")
    }

    fn parse_toml(content: &str) -> Self {
        let mut config = Self::default();
        let mut in_claude = false;
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') { continue; }
            if line.starts_with('[') && line.ends_with(']') {
                in_claude = &line[1..line.len() - 1] == "claude";
                continue;
            }
            if in_claude {
                if let Some((key, value)) = line.split_once('=') {
                    if key.trim() == "api_key" {
                        let v = value.trim().trim_matches('"');
                        if !v.is_empty() {
                            config.api_key = Some(v.to_string());
                        }
                    }
                }
            }
        }
        config
    }
}
