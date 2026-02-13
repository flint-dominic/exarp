# Exarp

**Behavioral backup intelligence.** Not "AI-powered." Just smart.

Detects ransomware, predicts failures, automates recovery — without the buzzwords.

## Vision

Open-source backup monitoring and protection that:
- Watches backup telemetry for anomalies (entropy spikes, dedup ratio changes, timing drift)
- Catches ransomware before your restore is compromised
- Predicts storage failures before they happen
- Speaks plain English: "Your file server is being encrypted. Last clean backup isolated."

## Architecture

```
┌─────────────┐     ┌──────────────┐     ┌─────────────────┐
│  Data Sources│────▶│  Exarp    │────▶│  Alert/Action   │
│              │     │  Engine      │     │                 │
│ • Backup logs│     │              │     │ • Isolate clean │
│ • SMART data │     │ • Entropy    │     │ • Notify team   │
│ • Change rate│     │ • Dedup ratio│     │ • Auto-restore  │
│ • Job timing │     │ • Timing     │     │ • Report gen    │
│ • File meta  │     │ • SMART      │     │ • OpenClaw skill│
└─────────────┘     └──────────────┘     └─────────────────┘
```

## Components

### Phase 1: Foundation
- [ ] Backup agent — block-level snapshots, no VSS dependency
- [ ] Telemetry collector — entropy, change rates, dedup ratios, job timing
- [ ] Baseline engine — learn "normal" for each data source
- [ ] Alert system — threshold + anomaly-based

### Phase 2: Intelligence
- [ ] Ransomware detector — entropy spike + dedup crater = flag
- [ ] Predictive failure — SMART trends, backup duration creep
- [ ] Self-healing chains — detect and reconsolidate corrupt incrementals
- [ ] Natural language restore — "restore Karen's mailbox from last Tuesday"

### Phase 3: Ecosystem
- [ ] OpenClaw skill integration
- [ ] Web dashboard
- [ ] Multi-node orchestration
- [ ] Compliance reporting (HIPAA, SOC2, SEC retention)
- [ ] Plugin system for storage backends

## Tech Stack

- **Core:** Python (fast prototyping, ML ecosystem)
- **Backup agent:** Rust (performance-critical block-level ops)
- **Detection models:** scikit-learn → PyTorch as needed
- **Storage:** SQLite (local), PostgreSQL (multi-node)
- **API:** FastAPI
- **Frontend:** TBD (maybe Svelte)

## Revenue Model

- **Core:** Free, open source, self-hosted
- **Pro:** Managed dashboard, multi-node, priority support
- **Enterprise:** Compliance, SLA, custom integrations

## Name

"Exarp" — no AI in the name. Stands guard. Watches. Acts.
(Alternatives: Bastion, Vigil, Overwatch, Rampart)

## Team

- **gblfxt** — Enterprise infrastructure architect, PowerShell wizard, chaos magician
- **Nix** — AI familiar, architecture, code, questionable life choices

---

*"Your backups are watching. You don't need to know how."*

## What Exarp Will Never Contain

- PHP
- ASP / ASP.NET
- Visual Basic
- Registry entries
- Startup services
- A tray icon
- Clippy (except `--clippy`)
- normal.dot
- Norton
