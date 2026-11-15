"""
CAPT — Task 5: Canary (Decoy) File Deployer
============================================
Generates high-entropy canary files in .docx, .pdf, and .xlsx formats
and deploys them into the target directories resolved by Task 4's
directory_mapper module.

These canary files act as digital tripwires: when ransomware modifies
them, the Watchdog agent (Task 6) detects the change and triggers the
incident response pipeline.

Design Decisions
----------------
- Canary filenames are prefixed with a tilde (~) so they sort to the top
  of directory listings, making them attractive early targets for
  ransomware that iterates alphabetically.
- Each canary embeds a high-entropy random payload so the file already
  has high entropy *before* any attack — the Watchdog will detect
  modification by comparing the file hash against the known-good hash
  stored in the deployment manifest, not by entropy alone.
- A JSON manifest (canary_manifest.json) is written to the project root
  recording every deployed canary's path, SHA-256 hash, size, and
  deployment timestamp for verification by downstream tasks.

Exports
-------
- deploy_canaries(sandbox=None) → dict
    Generates and deploys all canary files, returns the manifest dict.
- get_manifest_path() → Path
    Returns the path to the saved manifest JSON.

Usage
-----
    python canary_deployer.py            # sandbox mode (default)
    python canary_deployer.py --live     # live/VM mode
    python canary_deployer.py --clean    # remove all deployed canaries
"""

import hashlib
import json
import os
import secrets
import string
import sys
import platform
from datetime import datetime, timezone
from pathlib import Path

# ──────────────────────────────────────────────────────────────────────
#  Import Task 4 — Directory Mapper
# ──────────────────────────────────────────────────────────────────────
from directory_mapper import get_target_directories, SANDBOX_MODE

# ──────────────────────────────────────────────────────────────────────
#  CONFIGURATION
# ──────────────────────────────────────────────────────────────────────

# Canary filename prefix — tilde pushes files to the top of most
# directory listings, making them early ransomware targets.
CANARY_PREFIX: str = "~CAPT_canary"

# Canary file definitions: (extension, generator_function_name)
CANARY_EXTENSIONS: list[str] = [".docx", ".pdf", ".xlsx"]

# Size of random high-entropy payload embedded in each canary (bytes).
CANARY_PAYLOAD_SIZE: int = 4096

# Manifest filename
MANIFEST_FILENAME: str = "canary_manifest.json"


# ──────────────────────────────────────────────────────────────────────
#  HIGH-ENTROPY PAYLOAD GENERATOR (Task 3 Integration)
# ──────────────────────────────────────────────────────────────────────


def generate_entropy_payload(size: int = CANARY_PAYLOAD_SIZE) -> bytes:
    """
    Generate a cryptographically random byte string.
    This ensures the canary file has high Shannon entropy from creation,
    which is key to the CAPT detection model.
    """
    return secrets.token_bytes(size)


def generate_entropy_string(length: int = 64) -> str:
    """
    Generate a random high-entropy ASCII string (for text-based payloads).
    Uses the full printable ASCII range for maximum entropy per character.
    """
    alphabet = string.ascii_letters + string.digits + string.punctuation
    return "".join(secrets.choice(alphabet) for _ in range(length))


# ──────────────────────────────────────────────────────────────────────
#  CANARY FILE GENERATORS
# ──────────────────────────────────────────────────────────────────────


def _generate_docx(file_path: Path) -> None:
    """
    Generate a .docx canary file.

    Uses the python-docx library if available; otherwise falls back to
    writing a minimal Open XML .docx manually (a .docx is a ZIP archive
    with XML inside).
    """
    entropy_text = generate_entropy_string(256)
    marker = f"CAPT CANARY — DO NOT DELETE — {generate_entropy_string(32)}"

    try:
        from docx import Document

        doc = Document()
        doc.add_heading("CAPT Canary Document", level=1)
        doc.add_paragraph(marker)
        doc.add_paragraph(
            "This file is a decoy (canary) deployed by the CAPT framework. "
            "It is used for ransomware detection. Do not modify or delete."
        )
        # Embed high-entropy payload as a paragraph
        doc.add_paragraph(entropy_text)
        doc.save(str(file_path))

    except ImportError:
        # Fallback: write a minimal .docx (valid ZIP with content)
        import zipfile
        import io

        content_xml = f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:body>
    <w:p><w:r><w:t>{marker}</w:t></w:r></w:p>
    <w:p><w:r><w:t>{entropy_text}</w:t></w:r></w:p>
  </w:body>
</w:document>"""

        rels_xml = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1"
    Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument"
    Target="word/document.xml"/>
</Relationships>"""

        content_types_xml = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/word/document.xml"
    ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
</Types>"""

        with zipfile.ZipFile(file_path, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("[Content_Types].xml", content_types_xml)
            zf.writestr("_rels/.rels", rels_xml)
            zf.writestr("word/document.xml", content_xml)

    # Append raw entropy bytes to boost file entropy even further
    with open(file_path, "ab") as f:
        f.write(generate_entropy_payload())


def _generate_pdf(file_path: Path) -> None:
    """
    Generate a .pdf canary file.

    Uses reportlab if available; otherwise writes a minimal valid PDF
    manually with embedded high-entropy stream.
    """
    entropy_text = generate_entropy_string(256)
    marker = f"CAPT CANARY — DO NOT DELETE — {generate_entropy_string(32)}"

    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.pdfgen import canvas

        c = canvas.Canvas(str(file_path), pagesize=A4)
        c.setFont("Helvetica-Bold", 16)
        c.drawString(50, 780, "CAPT Canary Document")
        c.setFont("Helvetica", 10)
        c.drawString(50, 750, marker)
        c.drawString(50, 730, "This file is a decoy deployed by CAPT for ransomware detection.")
        # Embed entropy text
        y = 700
        for i in range(0, len(entropy_text), 80):
            c.drawString(50, y, entropy_text[i : i + 80])
            y -= 15
        c.save()

    except ImportError:
        # Fallback: write a minimal valid PDF with embedded entropy
        entropy_hex = generate_entropy_payload().hex()
        pdf_content = f"""%PDF-1.4
1 0 obj
<< /Type /Catalog /Pages 2 0 R >>
endobj
2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj
3 0 obj
<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792]
   /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>
endobj
4 0 obj
<< /Length {len(marker) + len(entropy_hex) + 50} >>
stream
BT
/F1 12 Tf
50 750 Td
({marker}) Tj
50 700 Td
({entropy_hex[:200]}) Tj
ET
endstream
endobj
5 0 obj
<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>
endobj
xref
0 6
0000000000 65535 f 
trailer
<< /Size 6 /Root 1 0 R >>
startxref
0
%%EOF"""
        file_path.write_text(pdf_content, encoding="utf-8")

    # Append raw entropy bytes
    with open(file_path, "ab") as f:
        f.write(generate_entropy_payload())


def _generate_xlsx(file_path: Path) -> None:
    """
    Generate a .xlsx canary file.

    Uses openpyxl if available; otherwise writes a minimal Open XML
    spreadsheet manually (a .xlsx is a ZIP archive with XML inside).
    """
    entropy_text = generate_entropy_string(256)
    marker = f"CAPT CANARY — DO NOT DELETE — {generate_entropy_string(32)}"

    try:
        from openpyxl import Workbook

        wb = Workbook()
        ws = wb.active
        ws.title = "CAPT Canary"
        ws["A1"] = "CAPT Canary Spreadsheet"
        ws["A2"] = marker
        ws["A3"] = "This file is a decoy deployed by CAPT for ransomware detection."
        # Fill cells with entropy data
        for i, chunk in enumerate(
            [entropy_text[j : j + 32] for j in range(0, len(entropy_text), 32)], start=4
        ):
            ws[f"A{i}"] = chunk
        wb.save(str(file_path))

    except ImportError:
        # Fallback: write a minimal .xlsx (valid ZIP with XML)
        import zipfile

        sheet_xml = f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
  <sheetData>
    <row r="1"><c r="A1" t="inlineStr"><is><t>{marker}</t></is></c></row>
    <row r="2"><c r="A2" t="inlineStr"><is><t>{entropy_text}</t></is></c></row>
  </sheetData>
</worksheet>"""

        workbook_xml = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"
          xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
  <sheets><sheet name="CAPT Canary" sheetId="1" r:id="rId1"/></sheets>
</workbook>"""

        rels_xml = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1"
    Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument"
    Target="xl/workbook.xml"/>
</Relationships>"""

        wb_rels_xml = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1"
    Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet"
    Target="worksheets/sheet1.xml"/>
</Relationships>"""

        content_types_xml = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/xl/workbook.xml"
    ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>
  <Override PartName="/xl/worksheets/sheet1.xml"
    ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>
</Types>"""

        with zipfile.ZipFile(file_path, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("[Content_Types].xml", content_types_xml)
            zf.writestr("_rels/.rels", rels_xml)
            zf.writestr("xl/workbook.xml", workbook_xml)
            zf.writestr("xl/_rels/workbook.xml.rels", wb_rels_xml)
            zf.writestr("xl/worksheets/sheet1.xml", sheet_xml)

    # Append raw entropy bytes
    with open(file_path, "ab") as f:
        f.write(generate_entropy_payload())


# Map extensions to their generator functions
_GENERATORS: dict = {
    ".docx": _generate_docx,
    ".pdf": _generate_pdf,
    ".xlsx": _generate_xlsx,
}


# ──────────────────────────────────────────────────────────────────────
#  HASHING & MANIFEST
# ──────────────────────────────────────────────────────────────────────


def _sha256(file_path: Path) -> str:
    """Compute SHA-256 hash of a file."""
    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def get_manifest_path() -> Path:
    """Return the path to the canary deployment manifest."""
    return Path(__file__).resolve().parent / MANIFEST_FILENAME


def _save_manifest(manifest: dict) -> Path:
    """Write the manifest dict to disk as JSON."""
    path = get_manifest_path()
    with open(path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2, default=str)
    return path


def load_manifest() -> dict | None:
    """Load and return the existing manifest, or None if not found."""
    path = get_manifest_path()
    if path.exists():
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    return None


# ──────────────────────────────────────────────────────────────────────
#  DEPLOYMENT
# ──────────────────────────────────────────────────────────────────────


def deploy_canaries(sandbox: bool | None = None) -> dict:
    """
    Generate and deploy all canary files into the target directories.

    Parameters
    ----------
    sandbox : bool, optional
        Override the module-level SANDBOX_MODE. If None, uses SANDBOX_MODE.

    Returns
    -------
    dict — The deployment manifest containing:
        - deployed_at : ISO 8601 timestamp
        - mode        : "sandbox" or "live"
        - platform    : OS info
        - canaries    : list of dicts with path, sha256, size_bytes, extension
    """
    mode = sandbox if sandbox is not None else SANDBOX_MODE
    target_dirs = get_target_directories(sandbox=mode)

    canaries: list[dict] = []

    for target_dir in target_dirs:
        for ext in CANARY_EXTENSIONS:
            filename = f"{CANARY_PREFIX}{ext}"
            file_path = target_dir / filename

            # Generate the canary file
            generator = _GENERATORS[ext]
            generator(file_path)

            # Record metadata
            canaries.append({
                "path": str(file_path),
                "directory": str(target_dir),
                "filename": filename,
                "extension": ext,
                "sha256": _sha256(file_path),
                "size_bytes": file_path.stat().st_size,
            })

    manifest = {
        "deployed_at": datetime.now(timezone.utc).isoformat(),
        "mode": "sandbox" if mode else "live",
        "platform": f"{platform.system()} {platform.release()}",
        "total_canaries": len(canaries),
        "target_directories": [str(d) for d in target_dirs],
        "canaries": canaries,
    }

    # Save manifest to disk
    manifest_path = _save_manifest(manifest)
    manifest["manifest_path"] = str(manifest_path)

    return manifest


# ──────────────────────────────────────────────────────────────────────
#  CLEANUP
# ──────────────────────────────────────────────────────────────────────


def clean_canaries(sandbox: bool | None = None) -> list[str]:
    """
    Remove all deployed canary files from target directories.

    Returns a list of paths that were deleted.
    """
    mode = sandbox if sandbox is not None else SANDBOX_MODE
    target_dirs = get_target_directories(sandbox=mode)
    removed: list[str] = []

    for target_dir in target_dirs:
        for ext in CANARY_EXTENSIONS:
            file_path = target_dir / f"{CANARY_PREFIX}{ext}"
            if file_path.exists():
                file_path.unlink()
                removed.append(str(file_path))

    # Also remove the manifest
    manifest_path = get_manifest_path()
    if manifest_path.exists():
        manifest_path.unlink()
        removed.append(str(manifest_path))

    return removed


# ──────────────────────────────────────────────────────────────────────
#  VERIFICATION
# ──────────────────────────────────────────────────────────────────────


def verify_canaries() -> dict:
    """
    Verify deployed canaries against the manifest.

    Returns a dict with verification results for each canary:
        - status: "intact", "modified", or "missing"
        - expected_sha256, actual_sha256 (if file exists)
    """
    manifest = load_manifest()
    if manifest is None:
        return {"error": "No manifest found. Deploy canaries first."}

    results = []
    for canary in manifest.get("canaries", []):
        file_path = Path(canary["path"])
        result = {
            "path": canary["path"],
            "expected_sha256": canary["sha256"],
        }

        if not file_path.exists():
            result["status"] = "missing"
            result["actual_sha256"] = None
        else:
            actual_hash = _sha256(file_path)
            result["actual_sha256"] = actual_hash
            if actual_hash == canary["sha256"]:
                result["status"] = "intact"
            else:
                result["status"] = "modified"

        results.append(result)

    return {
        "verified_at": datetime.now(timezone.utc).isoformat(),
        "manifest_deployed_at": manifest.get("deployed_at"),
        "results": results,
    }


# ──────────────────────────────────────────────────────────────────────
#  CLI ENTRY POINT
# ──────────────────────────────────────────────────────────────────────


def _print_deployment_report(manifest: dict) -> None:
    """Pretty-print the deployment results."""
    print("=" * 64)
    print("  CAPT — Canary Deployer")
    print(f"  Mode       : {manifest['mode'].upper()}")
    print(f"  Platform   : {manifest['platform']}")
    print(f"  Deployed   : {manifest['deployed_at']}")
    print(f"  Canaries   : {manifest['total_canaries']}")
    print("=" * 64)

    for canary in manifest["canaries"]:
        print(f"\n  ✓ {canary['filename']}")
        print(f"    Path   : {canary['path']}")
        print(f"    SHA-256: {canary['sha256'][:16]}...")
        print(f"    Size   : {canary['size_bytes']:,} bytes")

    print(f"\n{'─' * 64}")
    print(f"  Manifest saved: {manifest.get('manifest_path', 'N/A')}")
    print(f"  Ready for Task 6 (Watchdog Monitoring): YES ✓")
    print("=" * 64)


if __name__ == "__main__":
    use_sandbox = "--live" not in sys.argv

    if "--clean" in sys.argv:
        removed = clean_canaries(sandbox=use_sandbox)
        if removed:
            print("Cleaned up canary files:")
            for r in removed:
                print(f"  ✗ {r}")
        else:
            print("No canary files found to clean.")
        sys.exit(0)

    if "--verify" in sys.argv:
        result = verify_canaries()
        if "error" in result:
            print(f"Error: {result['error']}")
        else:
            print("=" * 64)
            print("  CAPT — Canary Verification")
            print("=" * 64)
            for r in result["results"]:
                icon = {"intact": "✓", "modified": "⚠", "missing": "✗"}[r["status"]]
                print(f"  [{icon} {r['status'].upper()}] {r['path']}")
            print("=" * 64)
        sys.exit(0)

    manifest = deploy_canaries(sandbox=use_sandbox)
    _print_deployment_report(manifest)
