use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use colored::*;
use serde::{Deserialize, Serialize};
use std::process::Command;

use crate::config::ExarpConfig;

// ── Restic JSON types ──────────────────────────────────────────────

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Snapshot {
    pub short_id: String,
    pub id: Option<String>,
    pub time: String,
    pub hostname: String,
    pub paths: Vec<String>,
    pub tags: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
pub struct RepoStats {
    pub total_size: u64,
    pub total_file_count: u64,
    #[serde(default)]
    pub snapshots_count: Option<u64>,
}

#[derive(Debug, Deserialize)]
pub struct DiffStat {
    #[serde(default)]
    pub source_snapshot: Option<String>,
    #[serde(default)]
    pub target_snapshot: Option<String>,
    #[serde(default)]
    pub added: Option<Vec<DiffEntry>>,
    #[serde(default)]
    pub removed: Option<Vec<DiffEntry>>,
    #[serde(default)]
    pub changed: Option<Vec<DiffEntry>>,
}

#[derive(Debug, Deserialize)]
pub struct DiffEntry {
    pub path: String,
    #[serde(default)]
    pub size: Option<u64>,
}

#[derive(Debug, Deserialize)]
pub struct DiffSummary {
    #[serde(default)]
    pub files_new: u64,
    #[serde(default)]
    pub files_removed: u64,
    #[serde(default)]
    pub files_changed: u64,
    #[serde(default)]
    pub dirs_new: u64,
    #[serde(default)]
    pub dirs_removed: u64,
    #[serde(default)]
    pub data_added: u64,
    #[serde(default)]
    pub data_removed: u64,
}

// ── Restic runner ──────────────────────────────────────────────────

pub struct ResticRunner {
    binary: String,
    repository: Option<String>,
    password_file: Option<String>,
}

impl ResticRunner {
    pub fn new(
        binary: Option<String>,
        repo: Option<String>,
        password_file: Option<String>,
    ) -> Self {
        Self {
            binary: binary.unwrap_or_else(|| "restic".to_string()),
            repository: repo,
            password_file,
        }
    }

    pub fn from_config(config: &ExarpConfig) -> Self {
        Self::new(
            config.restic.binary.clone(),
            config.restic.repository.clone(),
            config.restic.password_file.clone(),
        )
    }

    /// Build a restic command with common args
    fn cmd(&self) -> Result<Command> {
        let mut cmd = Command::new(&self.binary);
        cmd.arg("--json");

        if let Some(ref repo) = self.repository {
            cmd.arg("-r").arg(repo);
        } else if std::env::var("RESTIC_REPOSITORY").is_err() {
            bail!("No repository specified. Use --repo, RESTIC_REPOSITORY env var, or config.toml");
        }

        if let Some(ref pf) = self.password_file {
            cmd.arg("--password-file").arg(pf);
        } else if std::env::var("RESTIC_PASSWORD_FILE").is_err()
            && std::env::var("RESTIC_PASSWORD").is_err()
        {
            // Check default location
            let home = std::env::var("HOME").unwrap_or_default();
            let default_pf = format!("{}/.exarp/restic_pass", home);
            if std::path::Path::new(&default_pf).exists() {
                cmd.arg("--password-file").arg(&default_pf);
            } else {
                bail!("No password specified. Use --password-file, RESTIC_PASSWORD_FILE env var, or ~/.exarp/restic_pass");
            }
        }

        Ok(cmd)
    }

    /// Run a restic command and return stdout
    fn run(&self, args: &[&str]) -> Result<String> {
        let mut cmd = self.cmd()?;
        for arg in args {
            cmd.arg(arg);
        }
        let output = cmd
            .output()
            .context(format!("Failed to run restic. Is '{}' in PATH?", self.binary))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!("restic failed (exit {}): {}", output.status, stderr.trim());
        }

        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }

    /// Run a restic command without --json (for check)
    fn run_raw(&self, args: &[&str]) -> Result<(String, String, i32)> {
        let mut cmd = Command::new(&self.binary);

        if let Some(ref repo) = self.repository {
            cmd.arg("-r").arg(repo);
        }
        if let Some(ref pf) = self.password_file {
            cmd.arg("--password-file").arg(pf);
        } else {
            let home = std::env::var("HOME").unwrap_or_default();
            let default_pf = format!("{}/.exarp/restic_pass", home);
            if std::path::Path::new(&default_pf).exists() {
                cmd.arg("--password-file").arg(&default_pf);
            }
        }

        for arg in args {
            cmd.arg(arg);
        }

        let output = cmd.output().context("Failed to run restic")?;
        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        let code = output.status.code().unwrap_or(-1);

        Ok((stdout, stderr, code))
    }

    // ── Public API ─────────────────────────────────────────────────

    /// List all snapshots
    pub fn snapshots(&self) -> Result<Vec<Snapshot>> {
        let json = self.run(&["snapshots"])?;
        let snaps: Vec<Snapshot> = serde_json::from_str(&json)
            .context("Failed to parse restic snapshots output")?;
        Ok(snaps)
    }

    /// Get repository stats
    pub fn stats(&self) -> Result<RepoStats> {
        let json = self.run(&["stats"])?;
        let stats: RepoStats = serde_json::from_str(&json)
            .context("Failed to parse restic stats output")?;
        Ok(stats)
    }

    /// Run integrity check
    pub fn check(&self) -> Result<(bool, String)> {
        let (stdout, stderr, code) = self.run_raw(&["check"])?;
        let output = if stderr.is_empty() { stdout } else { stderr };
        Ok((code == 0, output))
    }

    /// Diff two snapshots
    pub fn diff(&self, snap1: &str, snap2: &str) -> Result<DiffSummary> {
        let json = self.run(&["diff", snap1, snap2])?;

        // restic diff --json outputs one JSON object per line, last line is summary
        let lines: Vec<&str> = json.trim().lines().collect();
        if let Some(last) = lines.last() {
            let summary: DiffSummary = serde_json::from_str(last)
                .context("Failed to parse restic diff summary")?;
            Ok(summary)
        } else {
            bail!("No output from restic diff");
        }
    }
}

// ── Display helpers ────────────────────────────────────────────────

fn human_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;
    const TB: u64 = GB * 1024;

    if bytes >= TB {
        format!("{:.1} TB", bytes as f64 / TB as f64)
    } else if bytes >= GB {
        format!("{:.1} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.1} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

fn time_ago(time_str: &str) -> String {
    if let Ok(dt) = DateTime::parse_from_rfc3339(time_str) {
        let now = Utc::now();
        let diff = now.signed_duration_since(dt.with_timezone(&Utc));

        let hours = diff.num_hours();
        if hours < 1 {
            format!("{} min ago", diff.num_minutes())
        } else if hours < 24 {
            format!("{}h ago", hours)
        } else {
            format!("{}d ago", hours / 24)
        }
    } else {
        // Try without timezone
        time_str.chars().take(19).collect()
    }
}

// ── Commands ───────────────────────────────────────────────────────

pub fn cmd_status(runner: &ResticRunner, json_output: bool) -> Result<()> {
    let snaps = runner.snapshots()?;
    let stats = runner.stats()?;

    if json_output {
        let out = serde_json::json!({
            "snapshots": snaps.len(),
            "total_size": stats.total_size,
            "total_files": stats.total_file_count,
            "latest_snapshot": snaps.last().map(|s| &s.time),
            "hosts": snaps.iter().map(|s| s.hostname.clone()).collect::<std::collections::HashSet<_>>(),
        });
        println!("{}", serde_json::to_string_pretty(&out)?);
        return Ok(());
    }

    println!("{}", "╔══════════════════════════════════════╗".bright_cyan());
    println!("{}", "║     EXARP — RESTIC REPO STATUS       ║".bright_cyan());
    println!("{}", "╚══════════════════════════════════════╝".bright_cyan());
    println!();

    println!("  {} {}", "Snapshots:".bright_white(), snaps.len().to_string().bright_green());
    println!("  {} {}", "Total size:".bright_white(), human_bytes(stats.total_size).bright_green());
    println!("  {} {}", "Total files:".bright_white(), stats.total_file_count.to_string().bright_green());

    if let Some(latest) = snaps.last() {
        println!("  {} {} ({})", "Latest:".bright_white(), 
            latest.short_id.bright_yellow(),
            time_ago(&latest.time).bright_cyan());
    }

    // Unique hosts
    let hosts: std::collections::HashSet<_> = snaps.iter().map(|s| &s.hostname).collect();
    println!("  {} {}", "Hosts:".bright_white(), 
        hosts.iter().map(|h| h.bright_magenta().to_string()).collect::<Vec<_>>().join(", "));

    println!();
    Ok(())
}

pub fn cmd_snapshots(runner: &ResticRunner, json_output: bool) -> Result<()> {
    let snaps = runner.snapshots()?;

    if json_output {
        println!("{}", serde_json::to_string_pretty(&snaps)?);
        return Ok(());
    }

    println!("{}", "╔══════════════════════════════════════════════════════════╗".bright_cyan());
    println!("{}", "║              EXARP — RESTIC SNAPSHOTS                    ║".bright_cyan());
    println!("{}", "╚══════════════════════════════════════════════════════════╝".bright_cyan());
    println!();
    println!("  {} {:>10}  {:>12}  {}",
        "ID".bright_white().underline(),
        "HOST".bright_white().underline(),
        "AGE".bright_white().underline(),
        "PATHS".bright_white().underline());

    for snap in &snaps {
        let age = time_ago(&snap.time);
        let paths = snap.paths.join(", ");
        let age_color = if age.contains('d') {
            let days: i64 = age.trim_end_matches("d ago").parse().unwrap_or(0);
            if days > 7 { age.bright_red() } else { age.bright_yellow() }
        } else {
            age.bright_green()
        };

        println!("  {} {:>10}  {:>12}  {}",
            snap.short_id.bright_yellow(),
            snap.hostname.bright_magenta(),
            age_color,
            paths.dimmed());
    }

    println!();
    println!("  {} snapshots total", snaps.len().to_string().bright_green());
    println!();
    Ok(())
}

pub fn cmd_check(runner: &ResticRunner, json_output: bool) -> Result<()> {
    if !json_output {
        println!("{}", "  Running restic check...".dimmed());
    }

    let (healthy, output) = runner.check()?;

    if json_output {
        let out = serde_json::json!({
            "healthy": healthy,
            "output": output.trim(),
        });
        println!("{}", serde_json::to_string_pretty(&out)?);
        return Ok(());
    }

    if healthy {
        println!("  {} Repository integrity verified", "✓".bright_green());
        // Show key lines from output
        for line in output.lines() {
            let line = line.trim();
            if line.contains("no errors") || line.contains("check successful") {
                println!("  {} {}", "│".dimmed(), line.bright_green());
            } else if !line.is_empty() {
                println!("  {} {}", "│".dimmed(), line.dimmed());
            }
        }
    } else {
        println!("  {} Repository check FAILED", "✗".bright_red());
        for line in output.lines() {
            let line = line.trim();
            if line.to_lowercase().contains("error") {
                println!("  {} {}", "│".dimmed(), line.bright_red());
            } else {
                println!("  {} {}", "│".dimmed(), line);
            }
        }
    }

    println!();
    Ok(())
}

pub fn cmd_drift(runner: &ResticRunner, json_output: bool, config: &ExarpConfig) -> Result<()> {
    let snaps = runner.snapshots()?;

    if snaps.len() < 2 {
        if json_output {
            println!("{}", serde_json::json!({"error": "Need at least 2 snapshots for drift analysis"}));
        } else {
            println!("  {} Need at least 2 snapshots for drift analysis", "!".bright_yellow());
        }
        return Ok(());
    }

    if !json_output {
        println!("{}", "╔══════════════════════════════════════════════════════════╗".bright_cyan());
        println!("{}", "║              EXARP — SNAPSHOT DRIFT ANALYSIS             ║".bright_cyan());
        println!("{}", "╚══════════════════════════════════════════════════════════╝".bright_cyan());
        println!();
    }

    let mut alerts: Vec<serde_json::Value> = Vec::new();

    // Compare consecutive snapshots (last N pairs)
    let pairs: Vec<_> = snaps.windows(2).collect();
    let check_pairs = if pairs.len() > 5 { &pairs[pairs.len()-5..] } else { &pairs };

    for pair in check_pairs {
        let snap1 = &pair[0];
        let snap2 = &pair[1];

        if !json_output {
            println!("  {} {} → {}",
                "Δ".bright_cyan(),
                snap1.short_id.bright_yellow(),
                snap2.short_id.bright_yellow());
        }

        match runner.diff(&snap1.short_id, &snap2.short_id) {
            Ok(diff) => {
                let total_changes = diff.files_new + diff.files_removed + diff.files_changed;
                let change_pct = if diff.files_new + diff.files_changed > 0 {
                    // Rough percentage based on changes vs total (estimate)
                    (total_changes as f64 / (total_changes as f64 + 100.0)) * 100.0
                } else {
                    0.0
                };

                let mut pair_alerts = Vec::new();

                // Check for mass changes
                if change_pct > config.alerts.drift_file_change_pct {
                    pair_alerts.push(format!("HIGH DRIFT: {:.0}% files changed", change_pct));
                }

                // Check for mass deletion
                if diff.files_removed > 0 && diff.data_removed > diff.data_added {
                    let ratio = diff.data_removed as f64 / (diff.data_added.max(1)) as f64;
                    if ratio > 2.0 {
                        pair_alerts.push(format!("DATA LOSS: removed {}x more than added", ratio as u64));
                    }
                }

                if json_output {
                    alerts.push(serde_json::json!({
                        "from": snap1.short_id,
                        "to": snap2.short_id,
                        "files_new": diff.files_new,
                        "files_removed": diff.files_removed,
                        "files_changed": diff.files_changed,
                        "data_added": diff.data_added,
                        "data_removed": diff.data_removed,
                        "alerts": pair_alerts,
                    }));
                } else {
                    let status = if pair_alerts.is_empty() {
                        "OK".bright_green().to_string()
                    } else {
                        pair_alerts.join("; ").bright_red().to_string()
                    };

                    println!("    +{} new, -{} removed, ~{} changed | added {} / removed {}  [{}]",
                        diff.files_new.to_string().bright_green(),
                        diff.files_removed.to_string().bright_red(),
                        diff.files_changed.to_string().bright_yellow(),
                        human_bytes(diff.data_added).bright_green(),
                        human_bytes(diff.data_removed).bright_red(),
                        status);
                }
            }
            Err(e) => {
                if json_output {
                    alerts.push(serde_json::json!({
                        "from": snap1.short_id,
                        "to": snap2.short_id,
                        "error": e.to_string(),
                    }));
                } else {
                    println!("    {} {}", "Error:".bright_red(), e);
                }
            }
        }
    }

    // Check backup freshness
    if let Some(latest) = snaps.last() {
        if let Ok(dt) = DateTime::parse_from_rfc3339(&latest.time) {
            let hours_since = Utc::now()
                .signed_duration_since(dt.with_timezone(&Utc))
                .num_hours();
            let threshold = config.alerts.missed_backup_hours as i64;

            if hours_since > threshold {
                if json_output {
                    alerts.push(serde_json::json!({
                        "alert": "missed_backup",
                        "hours_since_last": hours_since,
                        "threshold": threshold,
                    }));
                } else {
                    println!();
                    println!("  {} Last backup was {}h ago (threshold: {}h)",
                        "⚠ STALE".bright_red().bold(),
                        hours_since.to_string().bright_red(),
                        threshold.to_string().dimmed());
                }
            } else if !json_output {
                println!();
                println!("  {} Last backup {}h ago (threshold: {}h)",
                    "✓".bright_green(),
                    hours_since.to_string().bright_green(),
                    threshold.to_string().dimmed());
            }
        }
    }

    if json_output {
        println!("{}", serde_json::to_string_pretty(&alerts)?);
    } else {
        println!();
    }

    Ok(())
}
