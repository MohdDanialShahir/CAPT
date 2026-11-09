"""
CAPT — Task 4: Target Deployment Directory Mapper
==================================================
Identifies, resolves, validates, and returns the list of target directories
where canary (decoy) files will be deployed.

Modes
-----
- SANDBOX_MODE = True  (default)
    Maps to safe local test directories under ./test_sandbox/ so we never
    risk modifying real host files during development and testing.

- SANDBOX_MODE = False  (live / VM mode)
    Dynamically resolves the actual OS user directories
    (e.g., ~/Desktop, ~/Documents).

Exports
-------
- get_target_directories()  → list[Path]
    Returns validated, writable, absolute directory paths ready for
    Task 5 (decoy deployment) and Task 6 (Watchdog monitoring).
"""

import os
import sys
import stat
import platform
from pathlib import Path

# ──────────────────────────────────────────────────────────────────────
#  CONFIGURATION
# ──────────────────────────────────────────────────────────────────────

# Toggle between sandbox (safe local dirs) and live (real OS user dirs).
# Default to True — always sandbox unless explicitly switched for VM testing.
SANDBOX_MODE: bool = True

# High-value user folders targeted for canary deployment.
# These mirror the directories ransomware typically encrypts first.
TARGET_FOLDER_NAMES: list[str] = [
    "Desktop",
    "Documents",
]

# Relative root for sandbox test directories (relative to project root).
SANDBOX_ROOT: str = "test_sandbox"

# ──────────────────────────────────────────────────────────────────────
#  PATH RESOLUTION
# ──────────────────────────────────────────────────────────────────────


def _get_project_root() -> Path:
    """Return the project root (directory containing this module)."""
    return Path(__file__).resolve().parent


def _resolve_sandbox_paths() -> list[Path]:
    """
    Build sandbox-mode paths under <project_root>/test_sandbox/.
    Directories are created automatically if they do not exist.
    """
    root = _get_project_root() / SANDBOX_ROOT
    paths: list[Path] = []
    for folder in TARGET_FOLDER_NAMES:
        dir_path = root / folder
        dir_path.mkdir(parents=True, exist_ok=True)
        paths.append(dir_path.resolve())
    return paths


def _resolve_live_paths() -> list[Path]:
    """
    Resolve real OS user directories via os.path.expanduser.
    No directories are created in live mode — they must already exist.
    """
    paths: list[Path] = []
    for folder in TARGET_FOLDER_NAMES:
        dir_path = Path(os.path.expanduser(f"~/{folder}"))
        paths.append(dir_path.resolve())
    return paths


# ──────────────────────────────────────────────────────────────────────
#  VALIDATION
# ──────────────────────────────────────────────────────────────────────


def _validate_directory(dir_path: Path) -> dict:
    """
    Validate a single directory path and return a status dict.

    Returns
    -------
    dict with keys:
        path      : str   — absolute path
        exists    : bool  — whether the directory exists
        writable  : bool  — whether the current user can write to it
        valid     : bool  — True only if exists AND writable
        error     : str | None — human-readable issue description
    """
    result = {
        "path": str(dir_path),
        "exists": False,
        "writable": False,
        "valid": False,
        "error": None,
    }

    if not dir_path.exists():
        result["error"] = "Directory does not exist"
        return result

    if not dir_path.is_dir():
        result["error"] = "Path exists but is not a directory"
        return result

    result["exists"] = True

    # Write-permission check (cross-platform)
    if os.access(dir_path, os.W_OK):
        result["writable"] = True
        result["valid"] = True
    else:
        result["error"] = "Directory exists but is not writable"

    return result


def validate_directories(directories: list[Path]) -> list[dict]:
    """Validate a list of directory paths and return their status dicts."""
    return [_validate_directory(d) for d in directories]


# ──────────────────────────────────────────────────────────────────────
#  PUBLIC API
# ──────────────────────────────────────────────────────────────────────


def get_target_directories(sandbox: bool | None = None) -> list[Path]:
    """
    Resolve and validate the target deployment directories.

    Parameters
    ----------
    sandbox : bool, optional
        Override the module-level SANDBOX_MODE for this call.
        If None (default), uses the module-level SANDBOX_MODE setting.

    Returns
    -------
    list[Path]
        Validated, writable, absolute directory paths.

    Raises
    ------
    RuntimeError
        If any target directory fails validation (does not exist or
        is not writable).  In sandbox mode this should never happen
        because the directories are created automatically.
    """
    mode = sandbox if sandbox is not None else SANDBOX_MODE

    if mode:
        directories = _resolve_sandbox_paths()
    else:
        directories = _resolve_live_paths()

    # Validate every resolved path
    results = validate_directories(directories)
    invalid = [r for r in results if not r["valid"]]

    if invalid:
        msgs = [f"  ✗ {r['path']} — {r['error']}" for r in invalid]
        raise RuntimeError(
            "Target directory validation failed:\n" + "\n".join(msgs)
        )

    return directories


def print_directory_report(sandbox: bool | None = None) -> None:
    """
    Pretty-print the resolved target directory map with validation
    status.  Useful for quick manual verification.
    """
    mode = sandbox if sandbox is not None else SANDBOX_MODE
    mode_label = "SANDBOX" if mode else "LIVE"

    print("=" * 64)
    print(f"  CAPT — Target Directory Mapper")
    print(f"  Mode       : {mode_label}")
    print(f"  Platform   : {platform.system()} {platform.release()}")
    print(f"  User Home  : {Path.home()}")
    print("=" * 64)

    if mode:
        directories = _resolve_sandbox_paths()
    else:
        directories = _resolve_live_paths()

    results = validate_directories(directories)

    for r in results:
        status = "✓ VALID" if r["valid"] else f"✗ INVALID ({r['error']})"
        print(f"\n  [{status}]")
        print(f"    Path     : {r['path']}")
        print(f"    Exists   : {r['exists']}")
        print(f"    Writable : {r['writable']}")

    valid_paths = [Path(r["path"]) for r in results if r["valid"]]
    print(f"\n{'─' * 64}")
    print(f"  Summary: {len(valid_paths)}/{len(results)} directories validated")
    print(f"  Ready for Task 5 (Decoy Deployment): "
          f"{'YES ✓' if len(valid_paths) == len(results) else 'NO ✗'}")
    print("=" * 64)


# ──────────────────────────────────────────────────────────────────────
#  CLI ENTRY POINT
# ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    # Allow quick override from CLI:  python directory_mapper.py --live
    use_sandbox = "--live" not in sys.argv

    print_directory_report(sandbox=use_sandbox)

    # Also demonstrate the importable API
    print("\n>>> get_target_directories() returned:")
    try:
        paths = get_target_directories(sandbox=use_sandbox)
        for p in paths:
            print(f"    {p}")
    except RuntimeError as e:
        print(f"    ERROR: {e}")
