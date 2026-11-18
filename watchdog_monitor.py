"""
CAPT — Task 6: Watchdog File-System Monitoring Agent
=====================================================
Real-time monitoring of canary files using the `watchdog` library.
When a canary file is modified, deleted, or moved, this agent:

  1. Detects the event via OS-level filesystem notifications
  2. Identifies the offending process (PID attribution via psutil)
  3. Validates the threat by comparing the file's SHA-256 hash
     against the known-good hash from the canary manifest
  4. Logs the full incident with forensic metadata
  5. (Future Task 9) Triggers automated process termination

This module integrates:
  - Task 4: directory_mapper  → target directories to watch
  - Task 5: canary_deployer  → manifest with known-good hashes
  - Task 3: file_entropy_calculator → entropy analysis of modified files

Architecture
------------
    watchdog.Observer
         │
         ▼
    CanaryEventHandler (FileSystemEventHandler)
         │  on_modified / on_deleted / on_moved
         ▼
    _attribute_process()  →  PID, process name, cmdline via psutil
         │
         ▼
    _validate_threat()    →  hash comparison + entropy check
         │
         ▼
    _log_incident()       →  structured JSON incident log
         │
         ▼
    (Future) terminate_process()

Exports
-------
- start_watchdog(sandbox=None)   → starts the monitoring loop (blocking)
- CanaryEventHandler             → the event handler class (for testing)
- get_incident_log_path()        → Path to the incident log file

Usage
-----
    python watchdog_monitor.py              # sandbox mode (default)
    python watchdog_monitor.py --live       # live/VM mode
    python watchdog_monitor.py --test       # deploy canaries, start monitor,
                                            #   simulate attack, then stop
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
from watchdog.events import (
    FileSystemEventHandler,
    FileModifiedEvent,
    FileDeletedEvent,
    FileMovedEvent,
    FileCreatedEvent,
)

try:
    import psutil

    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

# ──────────────────────────────────────────────────────────────────────
#  Import CAPT Modules (Tasks 3, 4, 5)
# ──────────────────────────────────────────────────────────────────────
from directory_mapper import get_target_directories, SANDBOX_MODE
from canary_deployer import load_manifest, CANARY_PREFIX
from file_entropy_calculator import calculate_file_entropy

# ──────────────────────────────────────────────────────────────────────
#  CONFIGURATION
# ──────────────────────────────────────────────────────────────────────

# Incident log file (JSON Lines format — one JSON object per line)
INCIDENT_LOG_FILENAME: str = "incident_log.jsonl"

# Cooldown period (seconds) to prevent duplicate alerts for the same file
# (OS often fires multiple events for a single write operation)
EVENT_COOLDOWN_SECONDS: float = 2.0

# Entropy threshold — files above this are considered "encrypted"
# Normal office docs: ~3.0-6.0 bits/byte
# Encrypted/compressed: ~7.5-8.0 bits/byte
ENTROPY_THREAT_THRESHOLD: float = 7.5

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
    """Return the project root (directory containing this module)."""
    return Path(__file__).resolve().parent


def get_incident_log_path() -> Path:
    """Return the path to the incident log file."""
    return _get_project_root() / INCIDENT_LOG_FILENAME


def _sha256(file_path: Path) -> str:
    """Compute SHA-256 hash of a file."""
    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def _build_canary_lookup(manifest: dict) -> dict:
    """
    Build a fast lookup dict from the manifest:
        { normalized_path_str: canary_record_dict }
    """
    lookup = {}
    for canary in manifest.get("canaries", []):
        # Normalize path for consistent matching
        norm_path = str(Path(canary["path"]).resolve())
        lookup[norm_path] = canary
    return lookup


# ──────────────────────────────────────────────────────────────────────
#  PID ATTRIBUTION (Task 7 preview)
# ──────────────────────────────────────────────────────────────────────


def _attribute_process(file_path: str) -> dict:
    """
    Attempt to identify the process that has the given file open.

    Uses psutil to scan all running processes for open file handles
    matching the canary path. This is a best-effort heuristic —
    the offending process may have already closed the handle by the
    time we check.

    Returns
    -------
    dict with keys: pid, name, exe, cmdline, username, status
    """
    result = {
        "pid": None,
        "name": None,
        "exe": None,
        "cmdline": None,
        "username": None,
        "status": "unknown",
        "attribution_method": "none",
    }

    if not PSUTIL_AVAILABLE:
        result["status"] = "psutil_not_available"
        return result

    target = str(Path(file_path).resolve()).lower()

    # Strategy 1: Scan processes for open file handles
    for proc in psutil.process_iter(["pid", "name", "exe", "cmdline", "username"]):
        try:
            open_files = proc.open_files()
            for f in open_files:
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

    # Strategy 2: Check recently started processes (within last 10s)
    # that might have accessed the file and already closed the handle
    now = time.time()
    suspects = []
    for proc in psutil.process_iter(["pid", "name", "exe", "cmdline", "username", "create_time"]):
        try:
            if now - proc.info["create_time"] < 10:
                suspects.append(proc.info)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    if suspects:
        # Return the most recently created process as a suspect
        suspects.sort(key=lambda p: p["create_time"], reverse=True)
        suspect = suspects[0]
        result.update({
            "pid": suspect["pid"],
            "name": suspect["name"],
            "exe": suspect["exe"],
            "cmdline": suspect["cmdline"],
            "username": suspect["username"],
            "status": "suspected",
            "attribution_method": "recent_process_heuristic",
        })
        return result

    result["status"] = "unattributed"
    return result


# ──────────────────────────────────────────────────────────────────────
#  THREAT VALIDATION
# ──────────────────────────────────────────────────────────────────────


def _validate_threat(file_path: Path, canary_record: dict) -> dict:
    """
    Validate whether a canary file modification constitutes a threat.

    Checks:
    1. SHA-256 hash mismatch (definitive modification detection)
    2. File entropy level (high entropy = likely encrypted)
    3. File size change (ransomware often changes file size)

    Returns
    -------
    dict with keys: is_threat, threat_level, checks
    """
    result = {
        "is_threat": False,
        "threat_level": "none",  # none, low, medium, high, critical
        "checks": {},
    }

    if not file_path.exists():
        result["is_threat"] = True
        result["threat_level"] = "critical"
        result["checks"]["file_deleted"] = True
        return result

    # Check 1: Hash comparison
    current_hash = _sha256(file_path)
    expected_hash = canary_record["sha256"]
    hash_match = current_hash == expected_hash
    result["checks"]["hash_match"] = hash_match
    result["checks"]["expected_sha256"] = expected_hash
    result["checks"]["actual_sha256"] = current_hash

    # Check 2: Entropy analysis
    try:
        current_entropy = calculate_file_entropy(str(file_path))
        result["checks"]["entropy"] = round(current_entropy, 4)
        result["checks"]["entropy_threshold"] = ENTROPY_THREAT_THRESHOLD
        result["checks"]["entropy_exceeded"] = current_entropy >= ENTROPY_THREAT_THRESHOLD
    except Exception as e:
        result["checks"]["entropy_error"] = str(e)

    # Check 3: File size change
    current_size = file_path.stat().st_size
    expected_size = canary_record.get("size_bytes", 0)
    result["checks"]["expected_size"] = expected_size
    result["checks"]["actual_size"] = current_size
    result["checks"]["size_changed"] = current_size != expected_size

    # Threat classification
    if not hash_match:
        result["is_threat"] = True
        entropy_high = result["checks"].get("entropy_exceeded", False)
        size_changed = result["checks"]["size_changed"]

        if entropy_high and size_changed:
            result["threat_level"] = "critical"
        elif entropy_high or size_changed:
            result["threat_level"] = "high"
        else:
            result["threat_level"] = "medium"

    return result


# ──────────────────────────────────────────────────────────────────────
#  INCIDENT LOGGING
# ──────────────────────────────────────────────────────────────────────


def _log_incident(incident: dict) -> None:
    """
    Append a structured incident record to the JSON Lines log file.
    Each line is a standalone JSON object for easy parsing.
    """
    log_path = get_incident_log_path()
    with open(log_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(incident, default=str) + "\n")


# ──────────────────────────────────────────────────────────────────────
#  CANARY EVENT HANDLER
# ──────────────────────────────────────────────────────────────────────


class CanaryEventHandler(FileSystemEventHandler):
    """
    Watchdog event handler that monitors canary files for tampering.

    Only reacts to events involving known canary files (matched by
    the CANARY_PREFIX in the filename). Non-canary file events are
    silently ignored.
    """

    def __init__(self, canary_lookup: dict):
        """
        Parameters
        ----------
        canary_lookup : dict
            Mapping of normalized file paths → canary manifest records.
        """
        super().__init__()
        self.canary_lookup = canary_lookup
        self._last_event_times: dict[str, float] = {}
        self.incident_count: int = 0

    def _is_canary_file(self, path: str) -> bool:
        """Check if the event path corresponds to a known canary file."""
        filename = Path(path).name
        return filename.startswith(CANARY_PREFIX)

    def _is_cooldown(self, path: str) -> bool:
        """Check if we're in the cooldown window for this file."""
        norm = str(Path(path).resolve())
        now = time.time()
        last = self._last_event_times.get(norm, 0)
        if now - last < EVENT_COOLDOWN_SECONDS:
            return True
        self._last_event_times[norm] = now
        return False

    def _get_canary_record(self, path: str) -> dict | None:
        """Look up the canary manifest record for a given path."""
        norm = str(Path(path).resolve())
        return self.canary_lookup.get(norm)

    def _handle_canary_event(self, event_type: str, src_path: str, dest_path: str = None) -> None:
        """
        Core incident handling logic — called for any canary file event.
        """
        if self._is_cooldown(src_path):
            return

        file_path = Path(src_path)
        canary_record = self._get_canary_record(src_path)

        if canary_record is None:
            # Canary file detected by prefix but not in manifest
            # Could be a new file or a file we don't track
            logger.warning(f"Canary-like file event but not in manifest: {src_path}")
            return

        # ── Build Incident Record ──
        timestamp = datetime.now(timezone.utc).isoformat()

        logger.warning(
            f"🚨 CANARY TRIGGERED │ {event_type.upper()} │ {file_path.name} │ {file_path.parent}"
        )

        # PID Attribution
        process_info = _attribute_process(src_path)
        if process_info["status"] == "identified":
            logger.warning(
                f"   ► Process identified: PID {process_info['pid']} "
                f"({process_info['name']}) — {process_info['exe']}"
            )
        elif process_info["status"] == "suspected":
            logger.warning(
                f"   ► Suspected process: PID {process_info['pid']} "
                f"({process_info['name']}) — attribution: {process_info['attribution_method']}"
            )
        else:
            logger.warning(f"   ► Process attribution: {process_info['status']}")

        # Threat Validation
        if event_type == "deleted":
            threat_info = {
                "is_threat": True,
                "threat_level": "critical",
                "checks": {"file_deleted": True},
            }
        else:
            threat_info = _validate_threat(file_path, canary_record)

        threat_icon = {
            "none": "○",
            "low": "◔",
            "medium": "◑",
            "high": "◕",
            "critical": "●",
        }.get(threat_info["threat_level"], "?")

        logger.warning(
            f"   ► Threat Level: {threat_icon} {threat_info['threat_level'].upper()} "
            f"│ Is Threat: {threat_info['is_threat']}"
        )

        if threat_info.get("checks", {}).get("entropy") is not None:
            logger.info(
                f"   ► Entropy: {threat_info['checks']['entropy']:.4f} / 8.0000 bits/byte "
                f"(threshold: {ENTROPY_THREAT_THRESHOLD})"
            )

        # ── Assemble Full Incident ──
        incident = {
            "incident_id": f"CAPT-{int(time.time() * 1000)}",
            "timestamp": timestamp,
            "event_type": event_type,
            "canary_file": {
                "path": str(file_path),
                "filename": file_path.name,
                "directory": str(file_path.parent),
                "extension": file_path.suffix,
            },
            "process_attribution": process_info,
            "threat_assessment": threat_info,
            "platform": {
                "system": platform.system(),
                "release": platform.release(),
                "hostname": platform.node(),
            },
        }

        if dest_path:
            incident["canary_file"]["moved_to"] = dest_path

        # Log the incident
        _log_incident(incident)
        self.incident_count += 1

        logger.info(
            f"   ► Incident logged: {incident['incident_id']} "
            f"(total: {self.incident_count})"
        )

        # ── Future: Task 9 — Process Termination ──
        if threat_info["is_threat"] and process_info["pid"]:
            logger.warning(
                f"   ► [TASK 9 PLACEHOLDER] Would terminate PID {process_info['pid']} "
                f"({process_info['name']})"
            )

    # ── Watchdog Event Callbacks ──

    def on_modified(self, event):
        if event.is_directory:
            return
        if self._is_canary_file(event.src_path):
            self._handle_canary_event("modified", event.src_path)

    def on_deleted(self, event):
        if event.is_directory:
            return
        if self._is_canary_file(event.src_path):
            self._handle_canary_event("deleted", event.src_path)

    def on_moved(self, event):
        if event.is_directory:
            return
        if self._is_canary_file(event.src_path):
            self._handle_canary_event("moved", event.src_path, event.dest_path)

    def on_created(self, event):
        if event.is_directory:
            return
        if self._is_canary_file(event.src_path):
            logger.info(f"Canary file created: {event.src_path}")


# ──────────────────────────────────────────────────────────────────────
#  WATCHDOG OBSERVER
# ──────────────────────────────────────────────────────────────────────


def start_watchdog(sandbox: bool | None = None) -> None:
    """
    Start the Watchdog file-system monitoring agent.

    This is a blocking call — it runs until interrupted (Ctrl+C).

    Parameters
    ----------
    sandbox : bool, optional
        Override the module-level SANDBOX_MODE. If None, uses SANDBOX_MODE.
    """
    mode = sandbox if sandbox is not None else SANDBOX_MODE
    mode_label = "SANDBOX" if mode else "LIVE"

    # Load the canary manifest
    manifest = load_manifest()
    if manifest is None:
        logger.error(
            "No canary manifest found. Deploy canaries first:\n"
            "  python canary_deployer.py"
        )
        sys.exit(1)

    canary_lookup = _build_canary_lookup(manifest)

    # Resolve target directories
    target_dirs = get_target_directories(sandbox=mode)

    # Print startup banner
    print("=" * 64)
    print("  CAPT — Watchdog Monitoring Agent")
    print(f"  Mode          : {mode_label}")
    print(f"  Platform      : {platform.system()} {platform.release()}")
    print(f"  Canaries      : {len(canary_lookup)} files tracked")
    print(f"  Directories   : {len(target_dirs)} watched")
    print(f"  Incident Log  : {get_incident_log_path()}")
    print(f"  Cooldown      : {EVENT_COOLDOWN_SECONDS}s")
    print(f"  Entropy Threshold : {ENTROPY_THREAT_THRESHOLD} bits/byte")
    print("=" * 64)

    for d in target_dirs:
        print(f"  👁  Watching: {d}")
    print()

    for path, record in canary_lookup.items():
        print(f"  🔒 Tracking: {record['filename']} → {path}")
    print()
    print("  Press Ctrl+C to stop monitoring.")
    print("─" * 64)

    # Create event handler and observer
    event_handler = CanaryEventHandler(canary_lookup)
    observer = Observer()

    for target_dir in target_dirs:
        observer.schedule(event_handler, str(target_dir), recursive=False)

    # Start monitoring
    observer.start()
    logger.info("Watchdog monitoring agent started. Waiting for events...")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("Shutting down Watchdog monitoring agent...")
        observer.stop()

    observer.join()

    print()
    print("─" * 64)
    print(f"  Monitoring stopped. Total incidents: {event_handler.incident_count}")
    print(f"  Incident log: {get_incident_log_path()}")
    print("=" * 64)


# ──────────────────────────────────────────────────────────────────────
#  SELF-TEST MODE
# ──────────────────────────────────────────────────────────────────────


def run_self_test() -> bool:
    """
    Automated self-test:
    1. Deploy canaries (sandbox)
    2. Start Watchdog in background
    3. Simulate an attack (modify a canary)
    4. Verify incident was logged
    5. Clean up

    Returns True if test passed, False otherwise.
    """
    from canary_deployer import deploy_canaries, clean_canaries
    import threading

    print("=" * 64)
    print("  CAPT — Watchdog Self-Test")
    print("=" * 64)

    # Step 1: Deploy canaries
    print("\n  [1/5] Deploying canaries...")
    manifest = deploy_canaries(sandbox=True)
    canary_lookup = _build_canary_lookup(manifest)
    print(f"        Deployed {manifest['total_canaries']} canaries.")

    # Step 2: Start observer in background thread
    print("  [2/5] Starting Watchdog observer...")
    event_handler = CanaryEventHandler(canary_lookup)
    observer = Observer()

    target_dirs = get_target_directories(sandbox=True)
    for target_dir in target_dirs:
        observer.schedule(event_handler, str(target_dir), recursive=False)

    observer.start()
    time.sleep(1)  # Let observer settle
    print("        Observer running.")

    # Step 3: Simulate attack — modify a canary
    print("  [3/5] Simulating ransomware attack...")
    attack_target = manifest["canaries"][0]["path"]
    print(f"        Modifying: {attack_target}")

    with open(attack_target, "wb") as f:
        f.write(b"RANSOMWARE_ENCRYPTED_" + os.urandom(2048))

    # Give watchdog time to process the event
    time.sleep(3)

    # Step 4: Check results
    print("  [4/5] Checking results...")
    observer.stop()
    observer.join()

    incidents_logged = event_handler.incident_count
    print(f"        Incidents detected: {incidents_logged}")

    # Check the incident log
    log_path = get_incident_log_path()
    if log_path.exists():
        with open(log_path, "r") as f:
            lines = f.readlines()
        print(f"        Log entries: {len(lines)}")

        # Parse the last incident
        if lines:
            last_incident = json.loads(lines[-1])
            print(f"        Last incident ID: {last_incident['incident_id']}")
            print(f"        Threat level: {last_incident['threat_assessment']['threat_level']}")
            print(f"        Event type: {last_incident['event_type']}")

    # Step 5: Clean up
    print("  [5/5] Cleaning up...")
    clean_canaries(sandbox=True)
    if log_path.exists():
        log_path.unlink()
    print("        Cleaned up.")

    # Verdict
    passed = incidents_logged > 0
    print()
    print("─" * 64)
    if passed:
        print("  ✅ SELF-TEST PASSED — Watchdog detected the simulated attack!")
    else:
        print("  ❌ SELF-TEST FAILED — No incidents were detected.")
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
    start_watchdog(sandbox=use_sandbox)
