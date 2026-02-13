#[cfg(feature = "tui")]
mod dashboard;

use anyhow::Result;
use chrono::Utc;
use clap::{Parser, Subcommand};
use colored::*;
use indicatif::{ProgressBar, ProgressStyle};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

/// Exarp — Behavioral backup intelligence.
/// Detects ransomware, predicts failures, guards your data.
#[derive(Parser)]
#[command(name = "exarp", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// 📎 You know what this does.
    #[arg(long, hide = true)]
    clippy: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan a directory and establish an entropy baseline
    Scan {
        /// Path to scan
        path: PathBuf,
        /// Output baseline file (JSON)
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Sample size per file in bytes
        #[arg(long, default_value = "65536")]
        sample_size: usize,
    },
    /// Compare current state against a saved baseline
    Check {
        /// Path to scan
        path: PathBuf,
        /// Baseline file to compare against
        #[arg(short, long)]
        baseline: PathBuf,
        /// Entropy spike threshold (bits/byte)
        #[arg(long, default_value = "1.5")]
        threshold: f64,
    },
    /// Interactive TUI dashboard with live graphs (requires 'tui' feature)
    Dashboard,
    /// Watch a directory for changes (continuous monitoring)
    Watch {
        /// Path to watch
        path: PathBuf,
        /// Check interval in seconds
        #[arg(short, long, default_value = "300")]
        interval: u64,
        /// Webhook URL for alerts
        #[arg(long)]
        webhook: Option<String>,
    },
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct FileScan {
    path: String,
    entropy: f64,
    size: u64,
    extension: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct ScanResult {
    path: String,
    timestamp: String,
    total_files: usize,
    avg_entropy: f64,
    high_entropy_count: usize,  // > 7.5
    very_high_count: usize,     // > 7.9
    by_extension: HashMap<String, ExtStats>,
    suspicious: Vec<FileScan>,
}

#[derive(Debug, Serialize, Deserialize)]
struct ExtStats {
    count: usize,
    avg_entropy: f64,
}

#[derive(Debug, Serialize, Deserialize)]
struct Alert {
    severity: String,
    signal: String,
    message: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct CheckResult {
    timestamp: String,
    baseline_time: String,
    severity: String,
    entropy_delta: f64,
    alerts: Vec<Alert>,
}

/// Calculate Shannon entropy of a byte buffer (bits per byte)
fn entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut counts = [0u64; 256];
    for &byte in data {
        counts[byte as usize] += 1;
    }

    let len = data.len() as f64;
    let mut entropy = 0.0;

    for &count in &counts {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }

    entropy
}

/// Calculate entropy of a file, sampling first N bytes
fn file_entropy(path: &Path, sample_size: usize) -> Result<f64> {
    let mut file = fs::File::open(path)?;
    let mut buffer = vec![0u8; sample_size];
    let bytes_read = file.read(&mut buffer)?;
    buffer.truncate(bytes_read);

    if bytes_read < 64 {
        return Ok(0.0);
    }

    Ok(entropy(&buffer))
}

/// Collect all scannable file paths from a directory
fn collect_files(path: &Path) -> Vec<PathBuf> {
    let skip_dirs: std::collections::HashSet<&str> = [
        ".git", "node_modules", "__pycache__", ".cache", ".venv", "venv",
    ]
    .into_iter()
    .collect();

    WalkDir::new(path)
        .into_iter()
        .filter_entry(|e| {
            !e.file_name()
                .to_str()
                .map(|s| s.starts_with('.') || skip_dirs.contains(s))
                .unwrap_or(false)
                || e.depth() == 0
        })
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .filter(|e| e.metadata().map(|m| m.len() >= 64).unwrap_or(false))
        .map(|e| e.into_path())
        .collect()
}

/// Scan a directory and return results
fn scan_directory(path: &Path, sample_size: usize) -> Result<ScanResult> {
    let files = collect_files(path);
    let total = files.len();

    let pb = ProgressBar::new(total as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.cyan} [{bar:40.cyan/blue}] {pos}/{len} files ({eta})")
            .unwrap()
            .progress_chars("█▓░"),
    );

    // Parallel entropy calculation
    let scans: Vec<FileScan> = files
        .par_iter()
        .filter_map(|fpath| {
            pb.inc(1);
            let ent = file_entropy(fpath, sample_size).ok()?;
            let meta = fs::metadata(fpath).ok()?;
            let ext = fpath
                .extension()
                .and_then(|e| e.to_str())
                .map(|e| format!(".{}", e.to_lowercase()))
                .unwrap_or_default();

            Some(FileScan {
                path: fpath.to_string_lossy().to_string(),
                entropy: ent,
                size: meta.len(),
                extension: ext,
            })
        })
        .collect();

    pb.finish_and_clear();

    // Aggregate stats
    let total_files = scans.len();
    let avg_entropy = if total_files > 0 {
        scans.iter().map(|s| s.entropy).sum::<f64>() / total_files as f64
    } else {
        0.0
    };

    let high_entropy_count = scans.iter().filter(|s| s.entropy > 7.5).count();
    let very_high_count = scans.iter().filter(|s| s.entropy > 7.9).count();

    // By extension
    let mut ext_totals: HashMap<String, (usize, f64)> = HashMap::new();
    for scan in &scans {
        let entry = ext_totals.entry(scan.extension.clone()).or_insert((0, 0.0));
        entry.0 += 1;
        entry.1 += scan.entropy;
    }

    let by_extension: HashMap<String, ExtStats> = ext_totals
        .into_iter()
        .map(|(ext, (count, total))| {
            (
                ext,
                ExtStats {
                    count,
                    avg_entropy: total / count as f64,
                },
            )
        })
        .collect();

    // Suspicious files (>7.9 entropy, excluding known compressed types)
    let compressed_exts: std::collections::HashSet<&str> = [
        ".zip", ".gz", ".bz2", ".xz", ".7z", ".rar", ".zst",
        ".mp4", ".mkv", ".avi", ".mov", ".webm",
        ".mp3", ".ogg", ".flac", ".aac", ".opus",
        ".jpg", ".jpeg", ".png", ".webp", ".gif",
        ".jar", ".whl", ".deb", ".rpm",
    ]
    .into_iter()
    .collect();

    let suspicious: Vec<FileScan> = scans
        .iter()
        .filter(|s| s.entropy > 7.9 && !compressed_exts.contains(s.extension.as_str()))
        .cloned()
        .collect();

    Ok(ScanResult {
        path: path.to_string_lossy().to_string(),
        timestamp: Utc::now().to_rfc3339(),
        total_files,
        avg_entropy,
        high_entropy_count,
        very_high_count,
        by_extension,
        suspicious,
    })
}

/// Compare two scans
fn compare_scans(baseline: &ScanResult, current: &ScanResult, threshold: f64) -> CheckResult {
    let mut alerts = Vec::new();
    let ent_delta = current.avg_entropy - baseline.avg_entropy;

    // Overall entropy spike
    if ent_delta > threshold {
        alerts.push(Alert {
            severity: "CRITICAL".into(),
            signal: "entropy_spike".into(),
            message: format!(
                "Average entropy jumped {ent_delta:+.2} bits/byte ({:.2} → {:.2})",
                baseline.avg_entropy, current.avg_entropy
            ),
        });
    }

    // Mass encryption detection
    let vh_delta = current.very_high_count as i64 - baseline.very_high_count as i64;
    let vh_pct = if baseline.total_files > 0 {
        (vh_delta as f64 / baseline.total_files as f64) * 100.0
    } else {
        0.0
    };

    if vh_pct > 20.0 {
        alerts.push(Alert {
            severity: "CRITICAL".into(),
            signal: "mass_encryption".into(),
            message: format!(
                "{} new files with entropy >7.9 bits/byte ({:.0}% of files)",
                vh_delta, vh_pct
            ),
        });
    }

    // Per-extension anomalies
    let skip_exts: std::collections::HashSet<&str> =
        [".zip", ".gz", ".7z", ".jpg", ".png", ".mp4"]
            .into_iter()
            .collect();

    for (ext, cur_data) in &current.by_extension {
        if skip_exts.contains(ext.as_str()) {
            continue;
        }
        if let Some(base_data) = baseline.by_extension.get(ext) {
            let ext_delta = cur_data.avg_entropy - base_data.avg_entropy;
            if ext_delta > threshold {
                alerts.push(Alert {
                    severity: "HIGH".into(),
                    signal: "extension_entropy_shift".into(),
                    message: format!(
                        "{} files entropy jumped {ext_delta:+.2} ({:.2} → {:.2})",
                        ext, base_data.avg_entropy, cur_data.avg_entropy
                    ),
                });
            }
        }
    }

    // New suspicious files not in known-compressed categories
    if !current.suspicious.is_empty() && current.suspicious.len() > baseline.suspicious.len() + 5 {
        alerts.push(Alert {
            severity: "HIGH".into(),
            signal: "new_suspicious_files".into(),
            message: format!(
                "{} suspicious high-entropy files detected (was {})",
                current.suspicious.len(),
                baseline.suspicious.len()
            ),
        });
    }

    let severity = if alerts.iter().any(|a| a.severity == "CRITICAL") {
        "CRITICAL"
    } else if alerts.iter().any(|a| a.severity == "HIGH") {
        "HIGH"
    } else {
        "OK"
    }
    .to_string();

    CheckResult {
        timestamp: current.timestamp.clone(),
        baseline_time: baseline.timestamp.clone(),
        severity,
        entropy_delta: ent_delta,
        alerts,
    }
}

fn print_scan(result: &ScanResult) {
    println!("{}", "🛡️  Exarp Entropy Scanner".cyan().bold());
    println!("{}", "═".repeat(50).cyan());
    println!("  Path:           {}", result.path.white());
    println!("  Files scanned:  {}", result.total_files.to_string().white().bold());
    println!(
        "  Avg entropy:    {} bits/byte",
        format!("{:.4}", result.avg_entropy).white().bold()
    );
    println!(
        "  High (>7.5):    {}",
        result.high_entropy_count.to_string().yellow()
    );
    println!(
        "  Very high (>7.9): {}",
        result.very_high_count.to_string().red()
    );

    if !result.suspicious.is_empty() {
        println!(
            "\n{}",
            format!("  ⚠️  {} suspicious files:", result.suspicious.len())
                .yellow()
                .bold()
        );
        for f in result.suspicious.iter().take(10) {
            println!(
                "    {:.4} b/B  {:>10} bytes  {}",
                f.entropy,
                f.size,
                f.path.dimmed()
            );
        }
        if result.suspicious.len() > 10 {
            println!(
                "    ... and {} more",
                result.suspicious.len() - 10
            );
        }
    }

    // Top extensions by entropy
    let mut exts: Vec<_> = result.by_extension.iter().collect();
    exts.sort_by(|a, b| b.1.avg_entropy.partial_cmp(&a.1.avg_entropy).unwrap());

    println!("\n  {}", "Entropy by extension:".cyan());
    for (ext, stats) in exts.iter().take(15) {
        let bar_len = (stats.avg_entropy * 4.0) as usize;
        let bar = "█".repeat(bar_len.min(32));
        let bar_colored = if stats.avg_entropy > 7.9 {
            bar.red()
        } else if stats.avg_entropy > 7.0 {
            bar.yellow()
        } else {
            bar.green()
        };
        println!(
            "    {:>8}  {:.2}  {}  ({} files)",
            ext, stats.avg_entropy, bar_colored, stats.count
        );
    }
}

fn print_check(result: &CheckResult) {
    let severity_colored = match result.severity.as_str() {
        "CRITICAL" => result.severity.red().bold(),
        "HIGH" => result.severity.yellow().bold(),
        _ => result.severity.green().bold(),
    };

    println!("{}", "🛡️  Exarp Check".cyan().bold());
    println!("{}", "═".repeat(50).cyan());
    println!("  Status:         {}", severity_colored);
    println!(
        "  Entropy delta:  {} bits/byte",
        format!("{:+.4}", result.entropy_delta).white()
    );
    println!("  Baseline from:  {}", result.baseline_time.dimmed());

    if result.alerts.is_empty() {
        println!("\n  {} No anomalies detected.", "✅".green());
    } else {
        println!("\n  {} {} alert(s):", "🚨".red(), result.alerts.len());
        for alert in &result.alerts {
            let icon = match alert.severity.as_str() {
                "CRITICAL" => "🔴",
                "HIGH" => "🟡",
                _ => "🟢",
            };
            println!("    {} [{}] {}", icon, alert.signal, alert.message);
        }
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    if cli.clippy {
        println!();
        println!("  📎 It looks like you're trying to protect your data!");
        println!("     Would you like me to:");
        println!("     □ Actually help");
        println!("     □ Stare at you with dead eyes");
        println!("     □ Consume 4GB of RAM doing nothing");
        println!("     □ Crash during restore (my specialty!)");
        println!();
        println!("  📎 No? That's fine. I'll just be here. Watching.");
        println!("     ...I'm always watching.");
        println!();
        println!("  (In memory of Clippy, 1997-2007. You built character.)");
        println!();
        return Ok(());
    }

    let command = match cli.command {
        Some(cmd) => cmd,
        None => {
            println!("🦉 Exarp — Behavioral backup intelligence.");
            println!("   Run 'exarp --help' for usage.");
            return Ok(());
        }
    };

    match command {
        Commands::Dashboard => {
            #[cfg(feature = "tui")]
            return dashboard::run_dashboard();
            #[cfg(not(feature = "tui"))]
            anyhow::bail!("Dashboard requires the 'tui' feature. Rebuild with: cargo build --features tui");
        }
        Commands::Scan {
            path,
            output,
            sample_size,
        } => {
            let result = scan_directory(&path, sample_size)?;
            print_scan(&result);

            let out_path = output.unwrap_or_else(|| {
                let hash = format!("{:x}", md5_simple(path.to_string_lossy().as_bytes()));
                PathBuf::from(format!("/tmp/exarp_baseline_{}.json", &hash[..8]))
            });

            let json = serde_json::to_string_pretty(&result)?;
            fs::write(&out_path, &json)?;
            println!("\n  Baseline saved: {}", out_path.display().to_string().green());
        }

        Commands::Check {
            path,
            baseline,
            threshold,
        } => {
            let baseline_json = fs::read_to_string(&baseline)?;
            let baseline_data: ScanResult = serde_json::from_str(&baseline_json)?;
            let current = scan_directory(&path, 65536)?;
            let result = compare_scans(&baseline_data, &current, threshold);
            print_check(&result);

            if result.severity == "CRITICAL" {
                std::process::exit(2);
            } else if result.severity == "HIGH" {
                std::process::exit(1);
            }
        }

        Commands::Watch {
            path,
            interval,
            webhook: _,
        } => {
            println!("{}", "🛡️  Exarp Watch Mode".cyan().bold());
            println!("  Monitoring: {}", path.display());
            println!("  Interval: {}s", interval);
            println!("  Press Ctrl+C to stop\n");

            // Initial baseline
            println!("  Establishing baseline...");
            let mut baseline = scan_directory(&path, 65536)?;
            print_scan(&baseline);

            loop {
                std::thread::sleep(std::time::Duration::from_secs(interval));
                println!("\n  {} Rescanning...", "🔄".cyan());
                let current = scan_directory(&path, 65536)?;
                let result = compare_scans(&baseline, &current, 1.5);
                print_check(&result);

                if result.severity == "OK" {
                    // Update baseline on clean scan
                    baseline = current;
                } else {
                    println!(
                        "\n  {} Baseline preserved (last known clean state)",
                        "📌".yellow()
                    );
                }
            }
        }
    }

    Ok(())
}

/// Simple hash for baseline filenames (not crypto)
fn md5_simple(data: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf29ce484222325;
    for &byte in data {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}
