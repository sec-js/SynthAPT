use std::path::PathBuf;

#[derive(Debug, Clone, Default, PartialEq)]
pub enum Provider {
    #[default]
    Claude,
    Ollama,
}

/// Application configuration stored at ~/.config/SynthAPT/config.toml
#[derive(Debug, Clone)]
pub struct Config {
    pub api_key: Option<String>,
    pub provider: Provider,
    pub ollama_host: String,
    pub ollama_port: u16,
    pub ollama_model: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            api_key: None,
            provider: Provider::Claude,
            ollama_host: "127.0.0.1".to_string(),
            ollama_port: 11434,
            ollama_model: "qwen3:14b".to_string(),
        }
    }
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
        let mut lines = Vec::new();

        lines.push("[provider]".to_string());
        match self.provider {
            Provider::Claude => lines.push("backend = \"claude\"".to_string()),
            Provider::Ollama => lines.push("backend = \"ollama\"".to_string()),
        }
        lines.push(String::new());

        lines.push("[claude]".to_string());
        match &self.api_key {
            Some(key) => lines.push(format!("api_key = \"{}\"", key)),
            None => lines.push("# api_key = \"sk-ant-...\"".to_string()),
        }
        lines.push(String::new());

        lines.push("[ollama]".to_string());
        lines.push(format!("host = \"{}\"", self.ollama_host));
        lines.push(format!("port = {}", self.ollama_port));
        lines.push(format!("model = \"{}\"", self.ollama_model));
        lines.push(String::new());

        lines.join("\n")
    }

    fn parse_toml(content: &str) -> Self {
        let mut config = Self::default();
        let mut section = String::new();

        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') { continue; }
            if line.starts_with('[') && line.ends_with(']') {
                section = line[1..line.len() - 1].to_string();
                continue;
            }
            if let Some((key, value)) = line.split_once('=') {
                let key = key.trim();
                let value = value.trim().trim_matches('"');
                match section.as_str() {
                    "provider" => {
                        if key == "backend" {
                            config.provider = match value {
                                "ollama" => Provider::Ollama,
                                _ => Provider::Claude,
                            };
                        }
                    }
                    "claude" => {
                        if key == "api_key" && !value.is_empty() {
                            config.api_key = Some(value.to_string());
                        }
                    }
                    "ollama" => match key {
                        "host" => config.ollama_host = value.to_string(),
                        "port" => config.ollama_port = value.parse().unwrap_or(11434),
                        "model" => config.ollama_model = value.to_string(),
                        _ => {}
                    },
                    _ => {}
                }
            }
        }
        config
    }
}
