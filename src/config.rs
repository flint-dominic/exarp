use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct ExarpConfig {
    #[serde(default)]
    pub restic: ResticConfig,
    #[serde(default)]
    pub alerts: AlertConfig,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct ResticConfig {
    /// Path to restic binary (default: "restic" in PATH)
    pub binary: Option<String>,
    /// Repository URL (e.g., sftp:host:/path or /local/path)
    pub repository: Option<String>,
    /// Path to password file
    pub password_file: Option<String>,
    /// Expected backup interval in hours (alert if exceeded)
    pub expected_interval_hours: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AlertConfig {
    /// % of files changed between snapshots to flag as anomaly (default: 20)
    pub drift_file_change_pct: f64,
    /// % size decrease to flag as deletion attack (default: 10)
    pub drift_size_decrease_pct: f64,
    /// Hours without backup before alerting (default: 48)
    pub missed_backup_hours: u64,
}

impl Default for AlertConfig {
    fn default() -> Self {
        Self {
            drift_file_change_pct: 20.0,
            drift_size_decrease_pct: 10.0,
            missed_backup_hours: 48,
        }
    }
}

impl ExarpConfig {
    pub fn config_path() -> PathBuf {
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
        Path::new(&home).join(".exarp").join("config.toml")
    }

    pub fn load() -> Result<Self> {
        let path = Self::config_path();
        if path.exists() {
            let contents = std::fs::read_to_string(&path)?;
            let config: ExarpConfig = toml::from_str(&contents)?;
            Ok(config)
        } else {
            Ok(Self::default())
        }
    }

    pub fn save(&self) -> Result<()> {
        let path = Self::config_path();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let contents = toml::to_string_pretty(self)?;
        std::fs::write(&path, contents)?;
        Ok(())
    }

    /// Generate a default config file if none exists
    pub fn init() -> Result<()> {
        let path = Self::config_path();
        if path.exists() {
            println!("Config already exists at {}", path.display());
            return Ok(());
        }
        let config = Self::default();
        config.save()?;
        println!("Created default config at {}", path.display());
        Ok(())
    }
}
