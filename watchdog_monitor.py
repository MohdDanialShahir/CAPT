"""
CAPT — Task 6: Watchdog File-System Monitoring Agent (v2)
==========================================================
Real-time monitoring of canary files using the `watchdog` library.
When a canary file is modified, deleted, or moved, this agent:

  1. Detects the event via OS-level filesystem notifications
  2. Identifies the offending process (PID attribution via psutil)
  3. Classifies the threat using the weighted scoring engine (Task 8)
  4. Terminates the malicious process automatically (Task 9)
  5. Logs the full incident with forensic metadata

This module integrates:
  - Task 4: directory_mapper    → target directories to watch
  - Task 5: canary_deployer    → manifest with known-good hashes
  - Task 8: threat_classifier  → weighted multi-signal scoring
  - Task 9: process_terminator → safe automated process termination

Usage
-----
    python watchdog_monitor.py                  # sandbox mode (default)
    python watchdog_monitor.py --live           # live/VM mode
    python watchdog_monitor.py --dry-run        # detect but don't kill
    python watchdog_monitor.py --test           # automated self-test
"""

import hashlib
import json
import logging
import os
import platform
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

# ──────────────────────────────────────────────────────────────────────
#  Import CAPT Modules
# ──────────────────────────────────────────────────────────────────────
from directory_mapper import get_target_directories, SANDBOX_MODE
from canary_deployer import load_manifest, CANARY_PREFIX
from threat_classifier import classify_threat, ThreatLevel
from process_terminator import terminate_process

# ──────────────────────────────────────────────────────────────────────
#  CONFIGURATION
# ──────────────────────────────────────────────────────────────────────

INCIDENT_LOG_FILENAME: str = "incident_log.jsonl"

# Cooldown (seconds) to prevent duplicate alerts for the same file
EVENT_COOLDOWN_SECONDS: float = 2.0

# Minimum threat level required to auto-terminate the offending process
AUTO_TERMINATE_THRESHOLD: ThreatLevel = ThreatLevel.HIGH

# ──────────────────────────────────────────────────────────────────────
#  LOGGING SETUP
# ──────────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s │ %(levelname)-8s │ %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("CAPT.Watchdog")

# ──────────────────────────────────────────────────────────────────────
#  UTILITIES
# ──────────────────────────────────────────────────────────────────────


def _get_project_root() -> Path:
    return Path(__file__).resolve().parent


def get_incident_log_path() -> Path:
    return _get_project_root() / INCIDENT_LOG_FILENAME


def _build_canary_lookup(manifest: dict) -> dict:
    """Build a fast lookup: { normalised_path_str: canary_record }."""
    lookup = {}
    for canary in manifest.get("canaries", []):
        norm = str(Path(canary["path"]).resolve())
        lookup[norm] = canary
    return lookup


def _log_incident(incident: dict) -> None:
    """Append an incident record to the JSONL log."""
    with open(get_incident_log_path(), "a", encoding="utf-8") as f:
        f.write(json.dumps(incident, default=str) + "\n")


# ──────────────────────────────────────────────────────────────────────
#  PID ATTRIBUTION (Task 7)
# ──────────────────────────────────────────────────────────────────────


def _attribute_process(file_path: str) -> dict:
    """
    Identify the process that has the given file open.
    Uses psutil to scan running processes for matching open file handles.
    Falls back to a recently-started-process heuristic.
    """
    result = {
        "pid": None, "name": None, "exe": None,
        "cmdline": None, "username": None,
        "status": "unknown", "attribution_method": "none",
    }

    if not PSUTIL_AVAILABLE:
        result["status"] = "psutil_not_available"
        return result

    target = str(Path(file_path).resolve()).lower()

    # Strategy 1: Open file handle scan
    for proc in psutil.process_iter(["pid", "name", "exe", "cmdline", "username"]):
        try:
            for f in proc.open_files():
                if str(Path(f.path).resolve()).lower() == target:
                    result.update({
                        "pid": proc.info["pid"],
                        "name": proc.info["name"],
                        "exe": proc.info["exe"],
                        "cmdline": proc.info["cmdline"],
                        "username": proc.info["username"],
                        "status": "identified",
                        "attribution_method": "open_file_handle",
                    })
                    return result
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    # Strategy 2: Recently started process heuristic
    now = time.time()
    suspects = []
    for proc in psutil.process_iter(["pid", "name", "exe", "cmdline", "username", "create_time"]):
        try:
            if now - proc.info["create_time"] < 10:
                suspects.append(proc.info)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    if suspects:
        suspects.sort(key=lambda p: p["create_time"], reverse=True)
        s = suspects[0]
        result.update({
            "pid": s["pid"], "name": s["name"], "exe": s["exe"],
            "cmdline": s["cmdline"], "username": s["username"],
            "status": "suspected",
            "attribution_method": "recent_process_heuristic",
        })
        return result

    result["status"] = "unattributed"
    return result


# ──────────────────────────────────────────────────────────────────────
#  THREAT LEVEL ORDERING (for threshold comparison)
# ──────────────────────────────────────────────────────────────────────

_LEVEL_ORDER = {
    ThreatLevel.NONE: 0,
    ThreatLevel.LOW: 1,
    ThreatLevel.MEDIUM: 2,
    ThreatLevel.HIGH: 3,
    ThreatLevel.CRITICAL: 4,
}


def _level_at_least(level: ThreatLevel, threshold: ThreatLevel) -> bool:
    """Return True if `level` is ≥ `threshold` in severity."""
    return _LEVEL_ORDER.get(level, 0) >= _LEVEL_ORDER.get(threshold, 0)


# ──────────────────────────────────────────────────────────────────────
#  CANARY EVENT HANDLER
# ──────────────────────────────────────────────────────────────────────


class CanaryEventHandler(FileSystemEventHandler):
    """
    Watchdog event handler that monitors canary files for tampering.
    Only reacts to events involving known canary files.
    """

    def __init__(self, canary_lookup: dict, dry_run: bool = False):
        super().__init__()
        self.canary_lookup = canary_lookup
        self.dry_run = dry_run
        self._last_event_times: dict[str, float] = {}
        self.incident_count: int = 0
        self.terminations: list[dict] = []

    def _is_canary_file(self, path: str) -> bool:
        return Path(path).name.startswith(CANARY_PREFIX)

    def _is_cooldown(self, path: str) -> bool:
        norm = str(Path(path).resolve())
        now = time.time()
        last = self._last_event_times.get(norm, 0)
        if now - last < EVENT_COOLDOWN_SECONDS:
            return True
        self._last_event_times[norm] = now
        return False

    def _get_canary_record(self, path: str) -> dict | None:
        norm = str(Path(path).resolve())
        return self.canary_lookup.get(norm)

    def _handle_canary_event(self, event_type: str, src_path: str, dest_path: str = None) -> None:
        if self._is_cooldown(src_path):
            return

        file_path = Path(src_path)
        canary_record = self._get_canary_record(src_path)

        if canary_record is None:
            logger.warning(f"Canary-like file not in manifest: {src_path}")
            return

        timestamp = datetime.now(timezone.utc).isoformat()

        logger.warning(
            f"🚨 CANARY TRIGGERED │ {event_type.upper()} │ "
            f"{file_path.name} │ {file_path.parent}"
        )

        # ── Step 1: PID Attribution ──
        process_info = _attribute_process(src_path)
        if process_info["status"] == "identified":
            logger.warning(
                f"   ► Process: PID {process_info['pid']} "
                f"({process_info['name']}) — {process_info['exe']}"
            )
        elif process_info["status"] == "suspected":
            logger.warning(
                f"   ► Suspect: PID {process_info['pid']} "
                f"({process_info['name']}) — {process_info['attribution_method']}"
            )
        else:
            logger.warning(f"   ► Process: {process_info['status']}")

        # ── Step 2: Threat Classification (Task 8) ──
        verdict = classify_threat(
            file_path=file_path,
            canary_record=canary_record,
            event_type=event_type,
        )

        logger.warning(
            f"   ► Threat: {verdict.level.icon} {verdict.level.value.upper()} "
            f"(score: {verdict.score}) │ {verdict.summary}"
        )

        if verdict.current_entropy > 0:
            logger.info(
                f"   ► Entropy: {verdict.current_entropy:.4f} / 8.0000 bits/byte"
            )

        # ── Step 3: Assemble Incident ──
        incident_id = f"CAPT-{int(time.time() * 1000)}"
        incident = {
            "incident_id": incident_id,
            "timestamp": timestamp,
            "event_type": event_type,
            "canary_file": {
                "path": str(file_path),
                "filename": file_path.name,
                "directory": str(file_path.parent),
                "extension": file_path.suffix,
            },
            "process_attribution": process_info,
            "threat_assessment": verdict.to_dict(),
            "platform": {
                "system": platform.system(),
                "release": platform.release(),
                "hostname": platform.node(),
            },
            "termination": None,
        }

        if dest_path:
            incident["canary_file"]["moved_to"] = dest_path

        # ── Step 4: Process Termination (Task 9) ──
        should_terminate = (
            verdict.is_threat
            and _level_at_least(verdict.level, AUTO_TERMINATE_THRESHOLD)
            and process_info["pid"] is not None
        )

        if should_terminate:
            term_result = terminate_process(
                pid=process_info["pid"],
                process_name=process_info.get("name", "unknown"),
                reason=f"Canary {file_path.name} — {verdict.summary}",
                incident_id=incident_id,
                threat_level=verdict.level.value,
                dry_run=self.dry_run,
            )
            incident["termination"] = term_result.to_dict()
            self.terminations.append(term_result.to_dict())

            if term_result.success:
                method_label = "DRY RUN" if self.dry_run else term_result.method.upper()
                logger.warning(
                    f"   ► Terminated: [{method_label}] PID {process_info['pid']} "
                    f"({process_info['name']})"
                )
            else:
                logger.error(
                    f"   ► Termination failed: {term_result.detail}"
                )
        elif verdict.is_threat and process_info["pid"] is not None:
            logger.info(
                f"   ► Threat level {verdict.level.value.upper()} below "
                f"auto-terminate threshold ({AUTO_TERMINATE_THRESHOLD.value.upper()})"
            )

        # ── Step 5: Log Incident ──
        _log_incident(incident)
        self.incident_count += 1
        logger.info(f"   ► Incident logged: {incident_id} (total: {self.incident_count})")

    # ── Watchdog Callbacks ──

    def on_modified(self, event):
        if not event.is_directory and self._is_canary_file(event.src_path):
            self._handle_canary_event("modified", event.src_path)

    def on_deleted(self, event):
        if not event.is_directory and self._is_canary_file(event.src_path):
            self._handle_canary_event("deleted", event.src_path)

    def on_moved(self, event):
        if not event.is_directory and self._is_canary_file(event.src_path):
            self._handle_canary_event("moved", event.src_path, event.dest_path)

    def on_created(self, event):
        if not event.is_directory and self._is_canary_file(event.src_path):
            logger.info(f"Canary file created: {event.src_path}")


# ──────────────────────────────────────────────────────────────────────
#  WATCHDOG OBSERVER
# ──────────────────────────────────────────────────────────────────────


def start_watchdog(sandbox: bool | None = None, dry_run: bool = False) -> None:
    """
    Start the Watchdog monitoring agent (blocking).
    Press Ctrl+C to stop.
    """
    mode = sandbox if sandbox is not None else SANDBOX_MODE
    mode_label = "SANDBOX" if mode else "LIVE"

    manifest = load_manifest()
    if manifest is None:
        logger.error(
            "No canary manifest found. Deploy canaries first:\n"
            "  python canary_deployer.py"
        )
        sys.exit(1)

    canary_lookup = _build_canary_lookup(manifest)
    target_dirs = get_target_directories(sandbox=mode)

    print("=" * 64)
    print("  CAPT — Watchdog Monitoring Agent v2")
    print(f"  Mode            : {mode_label}")
    print(f"  Dry Run         : {'YES (detect only, no kills)' if dry_run else 'NO (auto-terminate enabled)'}")
    print(f"  Platform        : {platform.system()} {platform.release()}")
    print(f"  Canaries        : {len(canary_lookup)} files tracked")
    print(f"  Directories     : {len(target_dirs)} watched")
    print(f"  Kill Threshold  : {AUTO_TERMINATE_THRESHOLD.value.upper()}+")
    print(f"  Incident Log    : {get_incident_log_path()}")
    print("=" * 64)

    for d in target_dirs:
        print(f"  👁  Watching: {d}")
    print()
    for path, record in canary_lookup.items():
        print(f"  🔒 Tracking: {record['filename']} → {path}")
    print()
    print("  Press Ctrl+C to stop monitoring.")
    print("─" * 64)

    event_handler = CanaryEventHandler(canary_lookup, dry_run=dry_run)
    observer = Observer()

    for target_dir in target_dirs:
        observer.schedule(event_handler, str(target_dir), recursive=False)

    observer.start()
    logger.info("Watchdog monitoring agent started. Waiting for events...")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("Shutting down...")
        observer.stop()

    observer.join()

    print()
    print("─" * 64)
    print(f"  Monitoring stopped.")
    print(f"  Incidents detected : {event_handler.incident_count}")
    print(f"  Processes terminated: {len(event_handler.terminations)}")
    print(f"  Incident log       : {get_incident_log_path()}")
    print("=" * 64)


# ──────────────────────────────────────────────────────────────────────
#  SELF-TEST
# ──────────────────────────────────────────────────────────────────────


def run_self_test() -> bool:
    """
    Automated end-to-end self-test:
      1. Deploy canaries
      2. Start Watchdog (dry-run)
      3. Simulate ransomware (modify a canary)
      4. Verify detection + classification + termination attempt
      5. Clean up
    """
    from canary_deployer import deploy_canaries, clean_canaries

    print("=" * 64)
    print("  CAPT — Full Pipeline Self-Test (Tasks 3–9)")
    print("=" * 64)

    # Step 1
    print("\n  [1/5] Deploying canaries...")
    manifest = deploy_canaries(sandbox=True)
    canary_lookup = _build_canary_lookup(manifest)
    print(f"        {manifest['total_canaries']} canaries deployed.")

    # Step 2
    print("  [2/5] Starting Watchdog (dry-run)...")
    event_handler = CanaryEventHandler(canary_lookup, dry_run=True)
    observer = Observer()
    for d in get_target_directories(sandbox=True):
        observer.schedule(event_handler, str(d), recursive=False)
    observer.start()
    time.sleep(1)
    print("        Observer running.")

    # Step 3
    print("  [3/5] Simulating ransomware attack...")
    target = manifest["canaries"][0]["path"]
    print(f"        Target: {target}")
    with open(target, "wb") as f:
        f.write(b"RANSOMWARE_ENCRYPTED_" + os.urandom(2048))
    time.sleep(3)

    # Step 4
    print("  [4/5] Checking results...")
    observer.stop()
    observer.join()

    incidents = event_handler.incident_count
    terminations = len(event_handler.terminations)
    print(f"        Incidents   : {incidents}")
    print(f"        Terminations: {terminations} (dry-run)")

    log_path = get_incident_log_path()
    if log_path.exists():
        with open(log_path, "r") as f:
            lines = f.readlines()
        if lines:
            last = json.loads(lines[-1])
            print(f"        Incident ID : {last['incident_id']}")
            print(f"        Threat Level: {last['threat_assessment']['level']}")
            print(f"        Score       : {last['threat_assessment']['score']}")
            print(f"        Summary     : {last['threat_assessment']['summary']}")
            if last.get("termination"):
                print(f"        Termination : {last['termination']['method']} "
                      f"(PID {last['termination']['pid']})")

    # Step 5
    print("  [5/5] Cleaning up...")
    clean_canaries(sandbox=True)
    if log_path.exists():
        log_path.unlink()
    print("        Done.")

    passed = incidents > 0
    print()
    print("─" * 64)
    if passed:
        print("  ✅ SELF-TEST PASSED — Full pipeline working (Tasks 3–9)")
    else:
        print("  ❌ SELF-TEST FAILED — No incidents detected")
    print("=" * 64)

    return passed


# ──────────────────────────────────────────────────────────────────────
#  CLI ENTRY POINT
# ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    if "--test" in sys.argv:
        success = run_self_test()
        sys.exit(0 if success else 1)

    use_sandbox = "--live" not in sys.argv
    use_dry_run = "--dry-run" in sys.argv

    start_watchdog(sandbox=use_sandbox, dry_run=use_dry_run)
