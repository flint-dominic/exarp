# Exarp

**Behavioral backup intelligence.** Not "AI-powered." Just smart.

One binary. Scans your files. Learns what's normal. Screams when it's not.

---

## What It Does

Exarp monitors the **entropy** (randomness) of your files to detect threats like ransomware. Ransomware encrypts your files, and encrypted files have measurably higher entropy than normal ones. Exarp catches this.

**Normal text file:** ~4.5 bits/byte entropy  
**Normal JPEG:** ~7.7 bits/byte  
**Ransomware-encrypted file:** ~7.99 bits/byte  

Exarp scans your files, builds a baseline of what "normal" looks like, then alerts you when something changes dramatically. It's the smoke detector for your data.

## Quick Start

### 1. Download

Exarp is a single binary. No installer. No dependencies. No runtime.

| Platform | File | Size |
|----------|------|------|
| Linux x86_64 | `exarp` | 1.5 MB |
| Windows x86_64 | `exarp.exe` | 1.4 MB |
| macOS Intel | `exarp-macos-intel` | 1.1 MB |
| macOS Apple Silicon | `exarp-macos-arm` | 1.0 MB |

```bash
# Linux/macOS: make it executable
chmod +x exarp

# That's it. No install step.
```

### 2. Scan Something

```bash
# Scan a directory and see what's there
./exarp scan /home/yourname/Documents
```

This will output:
- Total files scanned
- Average entropy across all files
- Files with suspiciously high entropy (>7.9 bits/byte)
- Breakdown by file extension
- A saved baseline file (JSON) for future comparison

**Example output:**
```
🛡️  Exarp Entropy Scanner
══════════════════════════════════════════════════
  Path:           /home/yourname/Documents
  Files scanned:  12,847
  Avg entropy:    4.86 bits/byte
  High (>7.5):    342
  Very high (>7.9): 6

  ⚠️  6 suspicious files:
    7.9924 b/B  498164 bytes  /home/yourname/Documents/archive.zip
    7.9833 b/B  164439 bytes  /home/yourname/Documents/backup.7z
    ...

  Entropy by extension:
      .zip  7.89  ███████████████████████████████  (28 files)
      .jpg  7.71  ██████████████████████████████   (1204 files)
      .pdf  6.82  ██████████████████████████       (89 files)
      .docx 5.20  ████████████████████             (342 files)
      .txt  4.12  ████████████████                 (892 files)

  Baseline saved: /tmp/exarp_baseline_a1b2c3d4.json
```

**What "suspicious" means:** Files above 7.9 bits/byte are nearly maximally random — this is what encrypted data looks like. But it's also what compressed archives (.zip, .7z, .jar) look like. That's normal! Exarp tells you what it found; you decide if it's expected.

### 3. Check for Changes

Run the same scan later to compare against your baseline:

```bash
./exarp check /home/yourname/Documents
```

If ransomware encrypted your files between scans, you'd see:
```
🚨 ENTROPY SPIKE DETECTED
  Previous avg: 4.86 bits/byte
  Current avg:  7.94 bits/byte  (+3.08)
  Changed files: 12,841 of 12,847 (99.9%)
  
  ⚠️  This pattern is consistent with ransomware encryption.
  ⚠️  Last clean baseline: 2026-02-13 09:30:00
```

### 4. Watch Continuously

```bash
# Re-scan every 5 minutes, alert on changes
./exarp watch /home/yourname/Documents --interval 300
```

## Commands

| Command | What It Does |
|---------|-------------|
| `exarp scan <path>` | Scan a directory, save a baseline |
| `exarp check <path>` | Compare current state against last baseline |
| `exarp watch <path>` | Continuously monitor (scan on interval) |
| `exarp dashboard` | Launch terminal UI dashboard (see below) |
| `exarp --clippy` | 📎 "It looks like you're being ransomwared!" |

### Options

| Flag | Description |
|------|-------------|
| `--interval <seconds>` | How often to re-scan in watch mode (default: 300) |
| `--threshold <float>` | Entropy threshold for alerts (default: 7.9) |
| `--json` | Output results as JSON |
| `--quiet` | Only output alerts, not full scan results |
| `--baseline <path>` | Use a specific baseline file for comparison |

## Terminal Dashboard

Exarp includes a built-in terminal UI for real-time monitoring:

```bash
./exarp dashboard
```

This shows:
- **Entropy timeline** — a live graph of entropy readings over time using Braille characters
- **Source table** — all monitored paths with current status
- **Alert panel** — recent alerts and anomalies
- **Status spinner** — so you know it's alive

The dashboard supports multiple sources overlaid on the same graph, each with a unique color.

> **Note:** The TUI dashboard is a compile-time feature. Pre-built binaries include it. If building from source, use `cargo build --release --features tui`.

## Web Dashboard (PWA)

For remote monitoring, Exarp includes a Progressive Web App:

```bash
# Serve the web dashboard on port 8422
./exarp serve --port 8422
```

Then open `http://your-server:8422` in any browser. Works on phones and tablets — add to your home screen for an app-like experience.

Features:
- Live entropy line graphs
- Source cards with status indicators
- Alert panel with history
- 💀 **Sim Attack** button — simulates a ransomware entropy spike so you can see what detection looks like (demo only, doesn't touch your files)

## How Entropy Detection Works

Every file is made of bytes (values 0-255). **Entropy** measures how randomly distributed those bytes are:

- **Low entropy (0-3):** Very predictable. Think: a file full of zeros, or plain ASCII text with lots of repeated words.
- **Medium entropy (3-6):** Normal mixed content. Documents, source code, HTML.
- **High entropy (6-7.5):** Compressed or media files. JPEGs, PNGs, MP3s, PDFs with images.
- **Very high entropy (7.5-8.0):** Maximally random. Encrypted data, compressed archives, or... ransomware output.

The theoretical maximum is 8.0 bits/byte (perfectly random). Ransomware-encrypted files typically hit 7.95-7.99.

**The key insight:** Your files have a normal entropy profile that's relatively stable over time. When ransomware hits, that profile shifts dramatically and suddenly. Exarp watches for exactly this shift.

### Why Not Just Use Antivirus?

Antivirus looks for known malware signatures — it needs to recognize the specific ransomware. New ransomware (zero-day) bypasses it completely.

Exarp doesn't care *what* encrypted your files. It detects the *effect* — the entropy spike — regardless of the cause. It's behavioral detection, not signature matching.

## Supported Platforms

Exarp runs anywhere. It's a single static binary with zero dependencies.

- **Linux** x86_64 (tested on Ubuntu, Debian, Arch, Alpine)
- **Windows** x86_64 (Windows 10/11, Server 2016+)
- **macOS** Intel and Apple Silicon (Monterey+)
- **FreeBSD** (builds from source)

## Building From Source

```bash
# Requirements: Rust toolchain (rustup.rs)
git clone https://github.com/flint-dominic/exarp.git
cd exarp

# Standard build
cargo build --release

# With TUI dashboard
cargo build --release --features tui

# Binary is at target/release/exarp
```

## Roadmap

### v0.1 ✅ (Current)
- Entropy scanner
- Baseline save/compare
- Terminal dashboard (TUI)
- Web dashboard (PWA)
- Cross-platform binaries

### v0.2 (Next)
- TOML configuration file
- Restic/Borg/Kopia backup adapter — monitor backup health, not just files
- SSH remote scanning — scan machines from a central server
- Webhook alerts (Slack, Telegram, ntfy.sh, email)
- File-type awareness — knows that .jar and .zip are *supposed* to be high entropy

### v0.3
- `exarp doctor` — auto-detect backup tools and adapters on your system
- `exarp isolate` — tag last known clean backup
- `exarp restore` — guided restore from clean backup
- `exarp report` — generate incident report (PDF)
- DETECT → IDENTIFY → ISOLATE → RECOVER → REPORT pipeline

### v0.4
- Prometheus `/metrics` endpoint
- Grafana dashboard template
- Multi-source correlation (entropy + file count + backup duration)
- SMART disk health integration

### v1.0
- Stable API
- Plugin system for storage backends
- Compliance reporting templates (SOC2, HIPAA)
- Production-hardened, battle-tested

## Philosophy

**Read-only by design.** Exarp never writes to your data. Never. It scans, measures, and reports. Your files are sacred. We just watch over them.

**No services, no registry, no startup items.** Run it when you want. Cron it if you want. It doesn't install itself anywhere. Delete the binary to uninstall. That's it.

**No account required.** Download. Run. Done. No cloud, no signup, no telemetry, no phoning home.

**No AI in the name.** Entropy analysis is math, not magic. We don't need a buzzword to be useful.

## FAQ

**Q: Will this slow down my system?**  
A: Exarp scans at low I/O priority. A full scan of 67,000 files takes ~0.17 seconds on an SSD. You won't notice it.

**Q: What about false positives?**  
A: Compressed files (.zip, .7z, .jar, .gz) are naturally high-entropy. Exarp v0.2 will include file-type awareness to suppress expected high-entropy formats. For now, the scan output groups results by extension so you can easily spot normal compressed files vs. anomalies.

**Q: Can ransomware detect and evade Exarp?**  
A: Exarp is read-only and doesn't install itself. There's no process to kill, no service to disable, no registry key to delete. Ransomware would have to specifically target the binary file on disk, which requires knowing it exists and where it is. This is inherently harder to evade than signature-based detection.

**Q: Does it replace my backup software?**  
A: No. Exarp monitors and alerts. Your backup software (Restic, Borg, Veeam, Windows Backup, whatever) does the actual copying. Think of Exarp as the security camera watching your backup vault — it doesn't move the boxes, but it notices when someone's messing with them.

**Q: Why Rust?**  
A: Single binary, no runtime, fast, memory-safe. The same reasons you'd pick Rust for any systems tool. Also: no garbage collector pauses during time-critical scans.

**Q: What does "Exarp" mean?**  
A: It's a perfectly normal tech product name that definitely doesn't refer to an Enochian angel of the Air Watchtower. Don't look it up. Just trust your backups.

## What Exarp Will Never Contain

- PHP
- ASP / ASP.NET
- Visual Basic
- Registry entries
- Startup services that you didn't ask for
- A tray icon
- Clippy (except `--clippy`)
- normal.dot
- Anything Norton has ever touched
- The word "synergy" in any documentation

---

**Exarp** — Watches your data. Acts when it matters.

*Made by [flint-dominic](https://github.com/flint-dominic) and a familiar named Nix.*
