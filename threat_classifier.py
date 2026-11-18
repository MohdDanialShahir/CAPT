"""
CAPT — Task 8: Threat Classification Engine
=============================================
Standalone module that classifies canary file events into structured
threat levels using a weighted multi-signal scoring system.

Signals Analysed
----------------
1. SHA-256 hash mismatch    — definitive proof of modification
2. Shannon entropy level    — high entropy = likely encrypted
3. File size delta          — ransomware often changes file size
4. File deletion / rename   — destruction or evasion behaviour
5. Entropy delta            — change from original canary entropy

Threat Levels
-------------
  CRITICAL  — Strong encryption indicators (hash + entropy + size)
  HIGH      — Definitive modification with partial encryption signals
  MEDIUM    — Confirmed modification, inconclusive encryption signals
  LOW       — Minor anomaly, likely benign
  NONE      — No threat detected (file unchanged)

Scoring Model
-------------
Each signal carries a weight.  The sum determines the threat level:

  Signal                  Weight    Condition
  ─────────────────────── ──────    ─────────────────────────────
  hash_mismatch           40       SHA-256 ≠ manifest hash
  entropy_exceeded        25       entropy ≥ threshold (7.5 b/B)
  entropy_near_max        10       entropy ≥ 7.9 b/B (near-perfect)
  size_changed            15       file size ≠ manifest size
  file_deleted            50       file no longer exists
  file_renamed            45       file was moved/renamed
  rapid_modification      10       modified within 5s of creation
  ─────────────────────── ──────
  Total possible          ~105+ (signals can stack)

  Threat Level Thresholds:
    0       → NONE
    1-24    → LOW
    25-49   → MEDIUM
    50-74   → HIGH
    75+     → CRITICAL

Exports
-------
- classify_threat(file_path, canary_record, event_type, ...) → ThreatVerdict
- ThreatVerdict (dataclass) — structured result object
- ThreatLevel (enum)        — NONE, LOW, MEDIUM, HIGH, CRITICAL

Usage
-----
    from threat_classifier import classify_threat

    verdict = classify_threat(
        file_path=Path("test_sandbox/Desktop/~CAPT_canary.docx"),
        canary_record=manifest["canaries"][0],
        event_type="modified",
    )
    print(verdict.level)         # ThreatLevel.CRITICAL
    print(verdict.score)         # 90
    print(verdict.summary)       # "Hash mismatch + high entropy + size changed"
    print(verdict.is_threat)     # True
"""

from __future__ import annotations

import hashlib
import json
import platform
import sys
import time
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path
from datetime import datetime, timezone

from file_entropy_calculator import calculate_file_entropy

# ──────────────────────────────────────────────────────────────────────
#  CONFIGURATION
# ──────────────────────────────────────────────────────────────────────

# Entropy thresholds (bits per byte, max = 8.0)
ENTROPY_THREAT_THRESHOLD: float = 7.5     # "likely encrypted"
ENTROPY_NEAR_MAX_THRESHOLD: float = 7.9   # "almost certainly encrypted"

# Score thresholds for each threat level
SCORE_LOW: int = 1
SCORE_MEDIUM: int = 25
SCORE_HIGH: int = 50
SCORE_CRITICAL: int = 75

# Signal weights
WEIGHT_HASH_MISMATCH: int = 40
WEIGHT_ENTROPY_EXCEEDED: int = 25
WEIGHT_ENTROPY_NEAR_MAX: int = 10
WEIGHT_SIZE_CHANGED: int = 15
WEIGHT_FILE_DELETED: int = 50
WEIGHT_FILE_RENAMED: int = 45
WEIGHT_RAPID_MODIFICATION: int = 10

# Time window for "rapid modification" signal (seconds)
RAPID_MOD_WINDOW: float = 5.0


# ──────────────────────────────────────────────────────────────────────
#  DATA STRUCTURES
# ──────────────────────────────────────────────────────────────────────


class ThreatLevel(Enum):
    """Threat severity classification."""
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def icon(self) -> str:
        return {
            "none": "○",
            "low": "◔",
            "medium": "◑",
            "high": "◕",
            "critical": "●",
        }[self.value]

    @property
    def color_code(self) -> str:
        """ANSI color code for terminal output."""
        return {
            "none": "\033[92m",      # green
            "low": "\033[93m",       # yellow
            "medium": "\033[33m",    # orange
            "high": "\033[91m",      # red
            "critical": "\033[1;91m", # bold red
        }[self.value]


@dataclass
class SignalResult:
    """Result of a single threat signal check."""
    name: str
    triggered: bool
    weight: int
    detail: str

    @property
    def score(self) -> int:
        return self.weight if self.triggered else 0


@dataclass
class ThreatVerdict:
    """Complete threat classification result."""
    level: ThreatLevel
    score: int
    is_threat: bool
    summary: str
    signals: list[SignalResult]
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    # Raw check data for forensic logging
    file_path: str = ""
    event_type: str = ""
    expected_sha256: str = ""
    actual_sha256: str = ""
    expected_size: int = 0
    actual_size: int = 0
    original_entropy: float = 0.0
    current_entropy: float = 0.0

    def to_dict(self) -> dict:
        """Serialise to a JSON-compatible dict."""
        d = asdict(self)
        d["level"] = self.level.value
        d["signals"] = [asdict(s) for s in self.signals]
        return d

    def print_report(self) -> None:
        """Pretty-print the verdict to stdout."""
        rst = "\033[0m"
        clr = self.level.color_code
        print(f"\n  Threat Classification Report")
        print(f"  {'─' * 50}")
        print(f"  File       : {self.file_path}")
        print(f"  Event      : {self.event_type}")
        print(f"  Level      : {clr}{self.level.icon} {self.level.value.upper()}{rst}")
        print(f"  Score      : {self.score}")
        print(f"  Is Threat  : {'YES' if self.is_threat else 'NO'}")
        print(f"  Summary    : {self.summary}")
        print(f"  {'─' * 50}")
        print(f"  Signals:")
        for s in self.signals:
            icon = "✓" if s.triggered else "·"
            pts = f"+{s.weight}" if s.triggered else "  0"
            print(f"    {icon} [{pts:>3}] {s.name}: {s.detail}")
        print(f"  {'─' * 50}")
        print(f"  Total Score: {self.score} → {self.level.value.upper()}")
        print()


# ──────────────────────────────────────────────────────────────────────
#  UTILITY
# ──────────────────────────────────────────────────────────────────────


def _sha256(file_path: Path) -> str:
    """Compute SHA-256 hash of a file."""
    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def _score_to_level(score: int) -> ThreatLevel:
    """Map a numeric threat score to a ThreatLevel enum."""
    if score >= SCORE_CRITICAL:
        return ThreatLevel.CRITICAL
    elif score >= SCORE_HIGH:
        return ThreatLevel.HIGH
    elif score >= SCORE_MEDIUM:
        return ThreatLevel.MEDIUM
    elif score >= SCORE_LOW:
        return ThreatLevel.LOW
    else:
        return ThreatLevel.NONE


# ──────────────────────────────────────────────────────────────────────
#  CLASSIFICATION ENGINE
# ──────────────────────────────────────────────────────────────────────


def classify_threat(
    file_path: Path,
    canary_record: dict,
    event_type: str = "modified",
    event_timestamp: float | None = None,
) -> ThreatVerdict:
    """
    Classify a canary file event using weighted multi-signal scoring.

    Parameters
    ----------
    file_path : Path
        Path to the canary file that triggered the event.
    canary_record : dict
        The manifest record for this canary (sha256, size_bytes, etc.).
    event_type : str
        Type of filesystem event: "modified", "deleted", "moved", "created".
    event_timestamp : float, optional
        Unix timestamp of the event. Defaults to now.

    Returns
    -------
    ThreatVerdict
        Complete classification result with score, level, and signal details.
    """
    if event_timestamp is None:
        event_timestamp = time.time()

    signals: list[SignalResult] = []
    expected_hash = canary_record.get("sha256", "")
    expected_size = canary_record.get("size_bytes", 0)

    actual_hash = ""
    actual_size = 0
    current_entropy = 0.0
    original_entropy = canary_record.get("entropy", 0.0)

    # ── Signal 1: File Deleted ──
    if event_type == "deleted" or not file_path.exists():
        signals.append(SignalResult(
            name="file_deleted",
            triggered=True,
            weight=WEIGHT_FILE_DELETED,
            detail=f"Canary file was deleted: {file_path.name}",
        ))

        # Can't run further checks on a deleted file
        total = sum(s.score for s in signals)
        level = _score_to_level(total)
        return ThreatVerdict(
            level=level,
            score=total,
            is_threat=True,
            summary="Canary file deleted — likely ransomware or destructive action",
            signals=signals,
            file_path=str(file_path),
            event_type=event_type,
            expected_sha256=expected_hash,
            actual_sha256="N/A (deleted)",
            expected_size=expected_size,
            actual_size=0,
            original_entropy=original_entropy,
            current_entropy=0.0,
        )

    # ── Signal 2: File Renamed/Moved ──
    if event_type == "moved":
        signals.append(SignalResult(
            name="file_renamed",
            triggered=True,
            weight=WEIGHT_FILE_RENAMED,
            detail=f"Canary file was moved or renamed",
        ))

    # ── Signal 3: SHA-256 Hash Mismatch ──
    actual_hash = _sha256(file_path)
    hash_match = actual_hash == expected_hash
    signals.append(SignalResult(
        name="hash_mismatch",
        triggered=not hash_match,
        weight=WEIGHT_HASH_MISMATCH,
        detail=f"Expected {expected_hash[:16]}... → Got {actual_hash[:16]}..."
        if not hash_match else "Hash matches manifest",
    ))

    # ── Signal 4: Entropy Exceeded Threshold ──
    try:
        current_entropy = calculate_file_entropy(str(file_path))
    except Exception:
        current_entropy = 0.0

    entropy_exceeded = current_entropy >= ENTROPY_THREAT_THRESHOLD
    signals.append(SignalResult(
        name="entropy_exceeded",
        triggered=entropy_exceeded,
        weight=WEIGHT_ENTROPY_EXCEEDED,
        detail=f"Entropy: {current_entropy:.4f} / 8.0 (threshold: {ENTROPY_THREAT_THRESHOLD})",
    ))

    # ── Signal 5: Entropy Near Maximum ──
    entropy_near_max = current_entropy >= ENTROPY_NEAR_MAX_THRESHOLD
    signals.append(SignalResult(
        name="entropy_near_max",
        triggered=entropy_near_max,
        weight=WEIGHT_ENTROPY_NEAR_MAX,
        detail=f"Entropy {current_entropy:.4f} ≥ {ENTROPY_NEAR_MAX_THRESHOLD} "
               f"(near-perfect randomness)" if entropy_near_max
               else f"Entropy {current_entropy:.4f} < {ENTROPY_NEAR_MAX_THRESHOLD}",
    ))

    # ── Signal 6: File Size Changed ──
    actual_size = file_path.stat().st_size
    size_changed = actual_size != expected_size
    size_delta = actual_size - expected_size
    signals.append(SignalResult(
        name="size_changed",
        triggered=size_changed,
        weight=WEIGHT_SIZE_CHANGED,
        detail=f"Size: {expected_size:,} → {actual_size:,} bytes "
               f"(Δ {size_delta:+,})" if size_changed
               else f"Size unchanged: {actual_size:,} bytes",
    ))

    # ── Signal 7: Rapid Modification ──
    # Check if the event happened very soon after the file was last known
    # (indicates automated/scripted behaviour, not manual editing)
    deploy_time_str = canary_record.get("deployed_at", "")
    rapid_mod = False
    if deploy_time_str:
        try:
            # If file was modified very quickly after being accessed
            file_mtime = file_path.stat().st_mtime
            if event_timestamp - file_mtime < RAPID_MOD_WINDOW:
                rapid_mod = True
        except Exception:
            pass
    signals.append(SignalResult(
        name="rapid_modification",
        triggered=rapid_mod,
        weight=WEIGHT_RAPID_MODIFICATION,
        detail="File modified within rapid window — automated behaviour suspected"
        if rapid_mod else "Modification timing normal",
    ))

    # ── Calculate Total Score ──
    total_score = sum(s.score for s in signals)

    # If the hash matches the manifest, the file is unchanged — override
    # entropy signals that fire because our canaries are intentionally
    # high-entropy.  The hash is the ground truth.
    if hash_match and event_type != "moved":
        total_score = 0

    level = _score_to_level(total_score)
    is_threat = total_score >= SCORE_MEDIUM

    # ── Build Summary ──
    triggered_names = [s.name for s in signals if s.triggered]
    summary_parts = []
    if "hash_mismatch" in triggered_names:
        summary_parts.append("Hash mismatch")
    if "entropy_exceeded" in triggered_names:
        summary_parts.append("high entropy")
    if "size_changed" in triggered_names:
        summary_parts.append("size changed")
    if "file_deleted" in triggered_names:
        summary_parts.append("file deleted")
    if "file_renamed" in triggered_names:
        summary_parts.append("file renamed")
    if "rapid_modification" in triggered_names:
        summary_parts.append("rapid modification")

    if not summary_parts:
        summary = "No anomalies detected — canary file intact"
    else:
        summary = " + ".join(summary_parts)

    return ThreatVerdict(
        level=level,
        score=total_score,
        is_threat=is_threat,
        summary=summary,
        signals=signals,
        file_path=str(file_path),
        event_type=event_type,
        expected_sha256=expected_hash,
        actual_sha256=actual_hash,
        expected_size=expected_size,
        actual_size=actual_size,
        original_entropy=original_entropy,
        current_entropy=current_entropy,
    )


# ──────────────────────────────────────────────────────────────────────
#  CLI ENTRY POINT — Manual Testing
# ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import os
    import secrets
    from canary_deployer import deploy_canaries, load_manifest, clean_canaries

    print("=" * 64)
    print("  CAPT — Threat Classification Engine — Demo")
    print("=" * 64)

    # Deploy fresh canaries
    print("\n  [1] Deploying fresh canaries...")
    manifest = deploy_canaries(sandbox=True)

    canary = manifest["canaries"][0]
    target_path = Path(canary["path"])
    print(f"      Target: {target_path}")

    # Test 1: Unmodified file (should be NONE)
    print("\n  [2] Classifying UNMODIFIED canary...")
    v1 = classify_threat(target_path, canary, event_type="modified")
    v1.print_report()

    # Test 2: Simulate ransomware encryption
    print("  [3] Simulating ransomware encryption...")
    with open(target_path, "wb") as f:
        f.write(secrets.token_bytes(4096))

    v2 = classify_threat(target_path, canary, event_type="modified")
    v2.print_report()

    # Test 3: Simulate file deletion
    print("  [4] Simulating file deletion...")
    target_path.unlink()
    v3 = classify_threat(target_path, canary, event_type="deleted")
    v3.print_report()

    # Summary
    print("  " + "=" * 50)
    print(f"  Test 1 (intact)    : {v1.level.icon} {v1.level.value.upper()} (score: {v1.score})")
    print(f"  Test 2 (encrypted) : {v2.level.icon} {v2.level.value.upper()} (score: {v2.score})")
    print(f"  Test 3 (deleted)   : {v3.level.icon} {v3.level.value.upper()} (score: {v3.score})")
    print("  " + "=" * 50)

    # Clean up
    clean_canaries(sandbox=True)
    print("\n  Cleaned up. Done.")
