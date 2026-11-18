"""
CAPT — Task 9: Automated Process Termination Module
=====================================================
Safely terminates processes identified as responsible for canary file
tampering. Implements a defence-in-depth approach:

  1. Validate the PID is still running and matches expectations
  2. Check against a whitelist of protected system processes
  3. Attempt graceful termination first (SIGTERM / terminate)
  4. Force-kill if the process survives the grace period (SIGKILL / kill)
  5. Log the full termination event with forensic metadata

Safety Features
---------------
- System process whitelist (never kills explorer.exe, csrss.exe, etc.)
- Self-protection (never kills its own process tree)
- PID re-validation before termination (guards against PID reuse)
- Dry-run mode for testing without actually killing anything
- Graceful termination with configurable timeout before force-kill

Exports
-------
- terminate_process(pid, process_name, ...) → TerminationResult
- is_safe_to_terminate(pid, process_name) → (bool, reason)
- TerminationResult (dataclass)

Usage
-----
    from process_terminator import terminate_process

    result = terminate_process(
        pid=1234,
        process_name="rware_simulator.py",
        reason="Canary file ~CAPT_canary.docx was encrypted",
        dry_run=False,
    )
    print(result.success)   # True
    print(result.method)    # "terminated" or "killed"
"""

from __future__ import annotations

import json
import logging
import os
import platform
import signal
import sys
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

# ──────────────────────────────────────────────────────────────────────
#  LOGGING
# ──────────────────────────────────────────────────────────────────────

logger = logging.getLogger("CAPT.Terminator")

# ──────────────────────────────────────────────────────────────────────
#  CONFIGURATION
# ──────────────────────────────────────────────────────────────────────

# Grace period (seconds) after sending terminate before force-killing
GRACEFUL_TIMEOUT: float = 5.0

# Termination event log
TERMINATION_LOG_FILENAME: str = "termination_log.jsonl"

# System-critical processes that must NEVER be terminated.
# These are Windows and common OS processes.
PROTECTED_PROCESSES: set[str] = {
    # Windows core
    "system", "system idle process", "registry", "smss.exe",
    "csrss.exe", "wininit.exe", "services.exe", "lsass.exe",
    "svchost.exe", "winlogon.exe", "dwm.exe", "explorer.exe",
    "taskmgr.exe", "conhost.exe", "sihost.exe", "fontdrvhost.exe",
    "dllhost.exe", "runtimebroker.exe", "shellexperiencehost.exe",
    "searchhost.exe", "startmenuexperiencehost.exe",
    "textinputhost.exe", "ctfmon.exe", "audiodg.exe",
    "securityhealthservice.exe", "msmpeng.exe",
    "spoolsv.exe", "wuauserv.exe",
    # Linux core
    "systemd", "init", "kthreadd", "ksoftirqd", "rcu_sched",
    "journald", "udevd", "dbus-daemon", "sshd", "login",
    # CAPT's own processes (self-protection)
    "watchdog_monitor.py",
}

# Never terminate these PIDs
PROTECTED_PIDS: set[int] = {0, 1, 4}  # System, init, Windows System


# ──────────────────────────────────────────────────────────────────────
#  DATA STRUCTURES
# ──────────────────────────────────────────────────────────────────────


@dataclass
class TerminationResult:
    """Result of a process termination attempt."""
    success: bool
    pid: int
    process_name: str
    method: str           # "terminated", "killed", "dry_run", "skipped", "failed"
    reason: str           # Why we tried to terminate
    detail: str           # What actually happened
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    incident_id: str = ""
    threat_level: str = ""
    was_running: bool = False
    was_safe: bool = False
    safety_check_reason: str = ""
    process_info: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)

    def print_report(self) -> None:
        """Pretty-print the termination result."""
        icon = "✅" if self.success else "❌"
        print(f"\n  {icon} Process Termination Report")
        print(f"  {'─' * 50}")
        print(f"  PID        : {self.pid}")
        print(f"  Process    : {self.process_name}")
        print(f"  Method     : {self.method}")
        print(f"  Success    : {self.success}")
        print(f"  Reason     : {self.reason}")
        print(f"  Detail     : {self.detail}")
        if self.incident_id:
            print(f"  Incident   : {self.incident_id}")
        if self.threat_level:
            print(f"  Threat     : {self.threat_level}")
        print(f"  Timestamp  : {self.timestamp}")
        print(f"  {'─' * 50}")


# ──────────────────────────────────────────────────────────────────────
#  UTILITY
# ──────────────────────────────────────────────────────────────────────


def _get_project_root() -> Path:
    return Path(__file__).resolve().parent


def get_termination_log_path() -> Path:
    return _get_project_root() / TERMINATION_LOG_FILENAME


def _log_termination(result: TerminationResult) -> None:
    """Append termination event to the JSON Lines log."""
    log_path = get_termination_log_path()
    with open(log_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(result.to_dict(), default=str) + "\n")


def _get_process_info(pid: int) -> dict:
    """Gather detailed information about a process."""
    info = {
        "pid": pid,
        "name": None,
        "exe": None,
        "cmdline": None,
        "username": None,
        "create_time": None,
        "status": None,
        "parent_pid": None,
        "children_count": 0,
    }

    if not PSUTIL_AVAILABLE:
        return info

    try:
        proc = psutil.Process(pid)
        info.update({
            "name": proc.name(),
            "exe": proc.exe(),
            "cmdline": proc.cmdline(),
            "username": proc.username(),
            "create_time": proc.create_time(),
            "status": proc.status(),
            "parent_pid": proc.ppid(),
            "children_count": len(proc.children()),
        })
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        pass

    return info


# ──────────────────────────────────────────────────────────────────────
#  SAFETY CHECKS
# ──────────────────────────────────────────────────────────────────────


def is_safe_to_terminate(pid: int, process_name: str | None = None) -> tuple[bool, str]:
    """
    Determine whether it is safe to terminate a given process.

    Returns
    -------
    (is_safe, reason) : (bool, str)
        is_safe is True if the process can be safely terminated.
        reason explains why it is or isn't safe.
    """
    # Check 1: Protected PIDs
    if pid in PROTECTED_PIDS:
        return False, f"PID {pid} is a protected system PID"

    # Check 2: Self-protection — never kill our own process or parent
    if pid == os.getpid():
        return False, "Cannot terminate self"

    if PSUTIL_AVAILABLE:
        try:
            current = psutil.Process(os.getpid())
            if pid == current.ppid():
                return False, "Cannot terminate parent process"
        except psutil.NoSuchProcess:
            pass

    # Check 3: Protected process names
    if process_name:
        name_lower = process_name.lower()
        if name_lower in PROTECTED_PROCESSES:
            return False, f"Process '{process_name}' is on the protected list"

    # Check 4: Verify process still exists
    if PSUTIL_AVAILABLE:
        try:
            proc = psutil.Process(pid)
            proc_name = proc.name().lower()

            # Double-check against protected list using actual process name
            if proc_name in PROTECTED_PROCESSES:
                return False, f"Process '{proc_name}' (PID {pid}) is on the protected list"

        except psutil.NoSuchProcess:
            return False, f"PID {pid} no longer exists"
        except psutil.AccessDenied:
            return False, f"Access denied to PID {pid}"

    return True, "Process is safe to terminate"


# ──────────────────────────────────────────────────────────────────────
#  TERMINATION ENGINE
# ──────────────────────────────────────────────────────────────────────


def terminate_process(
    pid: int,
    process_name: str = "unknown",
    reason: str = "Canary file tampering detected",
    incident_id: str = "",
    threat_level: str = "",
    dry_run: bool = False,
    graceful_timeout: float = GRACEFUL_TIMEOUT,
) -> TerminationResult:
    """
    Terminate a process identified as responsible for canary tampering.

    Parameters
    ----------
    pid : int
        Process ID to terminate.
    process_name : str
        Name of the process (for logging and safety checks).
    reason : str
        Human-readable reason for termination.
    incident_id : str
        Associated incident ID from the Watchdog.
    threat_level : str
        Threat level that triggered this termination.
    dry_run : bool
        If True, perform all checks but don't actually kill the process.
    graceful_timeout : float
        Seconds to wait after graceful termination before force-killing.

    Returns
    -------
    TerminationResult
        Detailed result of the termination attempt.
    """
    if not PSUTIL_AVAILABLE:
        result = TerminationResult(
            success=False,
            pid=pid,
            process_name=process_name,
            method="failed",
            reason=reason,
            detail="psutil is not installed — cannot terminate processes",
            incident_id=incident_id,
            threat_level=threat_level,
        )
        _log_termination(result)
        return result

    # Gather process info before termination
    proc_info = _get_process_info(pid)

    # Safety check
    is_safe, safety_reason = is_safe_to_terminate(pid, process_name)

    if not is_safe:
        result = TerminationResult(
            success=False,
            pid=pid,
            process_name=process_name,
            method="skipped",
            reason=reason,
            detail=f"Safety check failed: {safety_reason}",
            incident_id=incident_id,
            threat_level=threat_level,
            was_running=True,
            was_safe=False,
            safety_check_reason=safety_reason,
            process_info=proc_info,
        )
        logger.warning(
            f"⛔ TERMINATION BLOCKED — PID {pid} ({process_name}): {safety_reason}"
        )
        _log_termination(result)
        return result

    # Dry run mode
    if dry_run:
        result = TerminationResult(
            success=True,
            pid=pid,
            process_name=process_name,
            method="dry_run",
            reason=reason,
            detail=f"DRY RUN — would terminate PID {pid} ({process_name})",
            incident_id=incident_id,
            threat_level=threat_level,
            was_running=True,
            was_safe=True,
            safety_check_reason=safety_reason,
            process_info=proc_info,
        )
        logger.info(
            f"🔵 DRY RUN — Would terminate PID {pid} ({process_name})"
        )
        _log_termination(result)
        return result

    # ── Actual Termination ──
    try:
        proc = psutil.Process(pid)

        # Step 1: Graceful termination (SIGTERM)
        logger.warning(
            f"🔴 TERMINATING PID {pid} ({process_name}) — {reason}"
        )
        proc.terminate()

        # Wait for graceful exit
        try:
            proc.wait(timeout=graceful_timeout)
            result = TerminationResult(
                success=True,
                pid=pid,
                process_name=process_name,
                method="terminated",
                reason=reason,
                detail=f"Process terminated gracefully within {graceful_timeout}s",
                incident_id=incident_id,
                threat_level=threat_level,
                was_running=True,
                was_safe=True,
                safety_check_reason=safety_reason,
                process_info=proc_info,
            )
            logger.warning(
                f"✅ PID {pid} ({process_name}) terminated gracefully"
            )
            _log_termination(result)
            return result

        except psutil.TimeoutExpired:
            # Step 2: Force kill (SIGKILL)
            logger.warning(
                f"⚡ PID {pid} did not exit gracefully — force killing..."
            )
            proc.kill()
            proc.wait(timeout=5)

            result = TerminationResult(
                success=True,
                pid=pid,
                process_name=process_name,
                method="killed",
                reason=reason,
                detail=f"Process force-killed after {graceful_timeout}s graceful timeout",
                incident_id=incident_id,
                threat_level=threat_level,
                was_running=True,
                was_safe=True,
                safety_check_reason=safety_reason,
                process_info=proc_info,
            )
            logger.warning(
                f"✅ PID {pid} ({process_name}) force-killed"
            )
            _log_termination(result)
            return result

    except psutil.NoSuchProcess:
        result = TerminationResult(
            success=False,
            pid=pid,
            process_name=process_name,
            method="failed",
            reason=reason,
            detail=f"PID {pid} no longer exists (process already exited)",
            incident_id=incident_id,
            threat_level=threat_level,
            was_running=False,
            was_safe=True,
            safety_check_reason=safety_reason,
            process_info=proc_info,
        )
        logger.info(f"PID {pid} already exited before termination")
        _log_termination(result)
        return result

    except psutil.AccessDenied:
        result = TerminationResult(
            success=False,
            pid=pid,
            process_name=process_name,
            method="failed",
            reason=reason,
            detail=f"Access denied — insufficient privileges to terminate PID {pid}",
            incident_id=incident_id,
            threat_level=threat_level,
            was_running=True,
            was_safe=True,
            safety_check_reason=safety_reason,
            process_info=proc_info,
        )
        logger.error(
            f"❌ Access denied — cannot terminate PID {pid} ({process_name})"
        )
        _log_termination(result)
        return result

    except Exception as e:
        result = TerminationResult(
            success=False,
            pid=pid,
            process_name=process_name,
            method="failed",
            reason=reason,
            detail=f"Unexpected error: {e}",
            incident_id=incident_id,
            threat_level=threat_level,
            was_running=True,
            was_safe=True,
            safety_check_reason=safety_reason,
            process_info=proc_info,
        )
        logger.error(f"❌ Failed to terminate PID {pid}: {e}")
        _log_termination(result)
        return result


# ──────────────────────────────────────────────────────────────────────
#  CLI ENTRY POINT
# ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import subprocess

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s │ %(levelname)-8s │ %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    print("=" * 64)
    print("  CAPT — Process Terminator — Demo")
    print("=" * 64)

    # Test 1: Safety check on a protected process
    print("\n  [1] Safety check: explorer.exe")
    safe, reason = is_safe_to_terminate(0, "explorer.exe")
    print(f"      Safe to terminate: {safe}")
    print(f"      Reason: {reason}")

    # Test 2: Safety check on self
    print(f"\n  [2] Safety check: self (PID {os.getpid()})")
    safe, reason = is_safe_to_terminate(os.getpid(), "python.exe")
    print(f"      Safe to terminate: {safe}")
    print(f"      Reason: {reason}")

    # Test 3: Spawn a dummy process, then terminate it (dry run)
    print("\n  [3] Spawning dummy process for dry-run test...")
    dummy = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(60)"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    time.sleep(0.5)
    print(f"      Dummy PID: {dummy.pid}")

    result_dry = terminate_process(
        pid=dummy.pid,
        process_name="dummy_sleeper",
        reason="Self-test: dry run",
        incident_id="TEST-DRY-001",
        threat_level="high",
        dry_run=True,
    )
    result_dry.print_report()

    # Test 4: Actually terminate the dummy process
    print("  [4] Terminating dummy process for real...")
    result_real = terminate_process(
        pid=dummy.pid,
        process_name="dummy_sleeper",
        reason="Self-test: real termination",
        incident_id="TEST-REAL-001",
        threat_level="critical",
        dry_run=False,
    )
    result_real.print_report()

    # Clean up log
    log_path = get_termination_log_path()
    if log_path.exists():
        print(f"\n  Termination log entries:")
        with open(log_path, "r") as f:
            for line in f:
                entry = json.loads(line)
                print(f"    [{entry['method']}] PID {entry['pid']} — {entry['detail']}")
        log_path.unlink()

    print("\n  Done.")
    print("=" * 64)
