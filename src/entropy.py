"""
Sentinel - Entropy Scanner

Calculates Shannon entropy of files/directories to establish baselines
and detect anomalous encryption (ransomware indicator).

Normal files: ~4-6 bits/byte (text, docs, mixed content)
Compressed:   ~7.5-7.9 bits/byte (zip, jpg - already compressed)  
Encrypted:    ~7.99+ bits/byte (ransomware output)

The trick: track entropy CHANGE over time, not absolute values.
A .zip is always high entropy. A .docx that jumps from 4.2 to 7.98 is a problem.
"""

import math
import os
import json
import hashlib
from collections import Counter
from pathlib import Path
from datetime import datetime, timezone


def file_entropy(filepath: str, sample_size: int = 65536) -> float:
    """Calculate Shannon entropy of a file (bits per byte).
    
    Samples first `sample_size` bytes for performance.
    Returns 0.0 for empty files.
    """
    try:
        with open(filepath, 'rb') as f:
            data = f.read(sample_size)
    except (PermissionError, OSError):
        return -1.0  # Can't read
    
    if not data:
        return 0.0
    
    counts = Counter(data)
    length = len(data)
    entropy = 0.0
    
    for count in counts.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    
    return entropy


def scan_directory(path: str, extensions: set = None) -> dict:
    """Scan a directory and return entropy statistics.
    
    Returns:
        {
            "path": "/some/dir",
            "timestamp": "ISO-8601",
            "total_files": int,
            "avg_entropy": float,
            "high_entropy_count": int,  # > 7.5 bits/byte
            "very_high_count": int,     # > 7.9 bits/byte
            "by_extension": {".docx": {"count": N, "avg_entropy": X}, ...},
            "files": [{"path": "...", "entropy": X, "size": N}, ...]
        }
    """
    results = {
        "path": str(path),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "total_files": 0,
        "avg_entropy": 0.0,
        "high_entropy_count": 0,
        "very_high_count": 0,
        "by_extension": {},
        "suspicious": [],
    }
    
    entropies = []
    ext_data = {}
    
    for root, dirs, files in os.walk(path):
        # Skip hidden dirs and common non-data dirs
        dirs[:] = [d for d in dirs if not d.startswith('.') and d not in ('node_modules', '__pycache__', '.git')]
        
        for fname in files:
            fpath = os.path.join(root, fname)
            ext = Path(fname).suffix.lower()
            
            if extensions and ext not in extensions:
                continue
            
            try:
                size = os.path.getsize(fpath)
            except OSError:
                continue
                
            if size == 0 or size < 64:  # Skip tiny files
                continue
            
            ent = file_entropy(fpath)
            if ent < 0:
                continue
            
            entropies.append(ent)
            results["total_files"] += 1
            
            if ent > 7.5:
                results["high_entropy_count"] += 1
            if ent > 7.9:
                results["very_high_count"] += 1
                results["suspicious"].append({
                    "path": fpath,
                    "entropy": round(ent, 4),
                    "size": size,
                    "ext": ext,
                })
            
            # Track by extension
            if ext not in ext_data:
                ext_data[ext] = {"count": 0, "total_entropy": 0.0}
            ext_data[ext]["count"] += 1
            ext_data[ext]["total_entropy"] += ent
    
    if entropies:
        results["avg_entropy"] = round(sum(entropies) / len(entropies), 4)
    
    for ext, data in ext_data.items():
        results["by_extension"][ext] = {
            "count": data["count"],
            "avg_entropy": round(data["total_entropy"] / data["count"], 4),
        }
    
    return results


def compare_scans(baseline: dict, current: dict, threshold: float = 1.5) -> dict:
    """Compare two scans and flag anomalies.
    
    Args:
        baseline: Previous scan results
        current: Current scan results  
        threshold: Entropy increase (bits) that triggers alert
    
    Returns alert dict with severity and details.
    """
    alerts = []
    
    # Overall entropy shift
    ent_delta = current["avg_entropy"] - baseline["avg_entropy"]
    if ent_delta > threshold:
        alerts.append({
            "severity": "CRITICAL",
            "signal": "entropy_spike",
            "message": f"Average entropy jumped {ent_delta:+.2f} bits/byte ({baseline['avg_entropy']:.2f} → {current['avg_entropy']:.2f})",
            "delta": ent_delta,
        })
    
    # Very high entropy file count change
    vh_delta = current["very_high_count"] - baseline["very_high_count"]
    vh_pct = (vh_delta / max(baseline["total_files"], 1)) * 100
    if vh_pct > 20:
        alerts.append({
            "severity": "CRITICAL", 
            "signal": "mass_encryption",
            "message": f"{vh_delta} new files with entropy >7.9 bits/byte ({vh_pct:.0f}% of files)",
            "new_suspicious_count": vh_delta,
        })
    
    # Per-extension anomalies
    for ext, cur_data in current["by_extension"].items():
        if ext in baseline["by_extension"]:
            base_data = baseline["by_extension"][ext]
            ext_delta = cur_data["avg_entropy"] - base_data["avg_entropy"]
            if ext_delta > threshold and ext not in ('.zip', '.gz', '.7z', '.jpg', '.png', '.mp4'):
                alerts.append({
                    "severity": "HIGH",
                    "signal": "extension_entropy_shift",
                    "message": f"{ext} files entropy jumped {ext_delta:+.2f} ({base_data['avg_entropy']:.2f} → {cur_data['avg_entropy']:.2f})",
                    "extension": ext,
                    "delta": ext_delta,
                })
    
    return {
        "timestamp": current["timestamp"],
        "baseline_time": baseline["timestamp"],
        "alerts": alerts,
        "severity": max((a["severity"] for a in alerts), default="OK"),
        "entropy_delta": round(ent_delta, 4),
    }


if __name__ == "__main__":
    import sys
    
    target = sys.argv[1] if len(sys.argv) > 1 else "."
    print(f"🛡️ Sentinel Entropy Scanner")
    print(f"Scanning: {target}\n")
    
    results = scan_directory(target)
    
    print(f"Files scanned: {results['total_files']}")
    print(f"Average entropy: {results['avg_entropy']:.4f} bits/byte")
    print(f"High entropy (>7.5): {results['high_entropy_count']}")
    print(f"Very high (>7.9): {results['very_high_count']}")
    
    if results["suspicious"]:
        print(f"\n⚠️ Suspicious files ({len(results['suspicious'])}):")
        for f in results["suspicious"][:10]:
            print(f"  {f['entropy']:.4f} b/B  {f['size']:>10,} bytes  {f['path']}")
    
    print(f"\nEntropy by extension:")
    sorted_exts = sorted(results["by_extension"].items(), key=lambda x: x[1]["avg_entropy"], reverse=True)
    for ext, data in sorted_exts[:15]:
        bar = "█" * int(data["avg_entropy"])
        print(f"  {ext:>8s}  {data['avg_entropy']:.2f} {bar}  ({data['count']} files)")
    
    # Save baseline
    baseline_path = f"/tmp/sentinel_baseline_{hashlib.md5(target.encode()).hexdigest()[:8]}.json"
    with open(baseline_path, 'w') as f:
        json.dump(results, f, indent=2)
    print(f"\nBaseline saved: {baseline_path}")
