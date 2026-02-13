# Exarp Architecture

## Core Insight

Backup software has two jobs:
1. Copy bits reliably
2. Know when something's wrong

Everyone focuses on #1. We're starting with #2.

## Why "No VSS"

VSS (Volume Shadow Copy Service) is Windows' mechanism for application-consistent snapshots.
It's also a cascading failure machine. Our approach:

- **Block-level snapshots** below the filesystem — OS doesn't get a vote
- **Application-native dumps** where consistency matters (SQL: `BACKUP DATABASE`, PG: `pg_dump`)
- **No handle negotiation** — we don't ask permission, we fork blocks

This means Linux-first (ZFS/Btrfs/LVM snapshots), with Windows support via:
- Direct block device access
- Hyper-V checkpoint API (bypass VSS for VMs)
- Or just... back up from the hypervisor, not inside the guest

## Ransomware Detection Engine

The killer feature. How it works:

### Signals
| Signal | Normal | Ransomware |
|--------|--------|------------|
| File entropy | ~4-6 bits/byte (mixed content) | ~7.9+ bits/byte (encrypted) |
| Dedup ratio | 60-80% savings | Near 0% (encrypted = unique) |
| Change rate | 1-5% of files per backup | 80%+ files changed |
| File extension distribution | Stable | Mass rename to .encrypted/.locked |
| Backup duration | Predictable ±10% | Spikes (more changed blocks) |

### Detection Logic
1. Maintain rolling baseline per data source (30-day window)
2. Each backup job generates a telemetry snapshot
3. Compare against baseline using z-scores
4. If 2+ signals exceed threshold simultaneously → ALERT
5. Automatically tag last-known-clean backup generation
6. Optional: prevent overwrite of clean backup (immutable flag)

### False Positive Mitigation
- Large software deployments trigger change rate spikes
- Compression/encryption tools legitimately raise entropy
- Solution: correlation across multiple signals, not single-trigger
- Cooldown period after admin-acknowledged events

## Backup Agent Design

### Block-Level (Linux)
```
LVM snapshot → read changed blocks via thin_delta → 
compress → encrypt → ship to target
```

### Block-Level (Windows) 
```
Hyper-V checkpoint OR direct volume shadow (our own, not VSS) →
read changed blocks via USN journal + bitmap →
compress → encrypt → ship to target
```

### Application-Aware (Optional Layer)
```
Pre-hook: call application's native backup command
Post-hook: verify integrity
Example: SQL Server → BACKUP DATABASE WITH CHECKSUM
```

## Storage Backends

Plugin architecture:
- Local filesystem
- S3-compatible (AWS, MinIO, Backblaze B2)
- SSH/rsync target
- NFS/SMB share
- Custom (implement BackendInterface)

## OpenClaw Integration

```yaml
# Exarp as an OpenClaw skill
- "backup yogsothoth" → triggers backup job
- "check backups" → health summary
- "restore /var/lib/postgres from yesterday" → guided restore
- Heartbeat integration → Exarp alerts flow through OpenClaw
```
