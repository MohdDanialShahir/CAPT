# CAPT — Canary-Based Automated Process Terminator

Lightweight Behavioral Ransomware Detection and Termination using High-Entropy Decoy Files, with Compliance Logging aligned to the Malaysian Cyber Security Act 2024 (Act 854).

> **⚠️ Educational / Research Project Only**
> This is a Final Year Project (FYP) for BSc (Hons) Computer Science (Cyber Security). All testing is conducted in isolated virtual machines using a custom ransomware simulator — no real malware is used.

---

## Problem

Malaysian SMEs are increasingly targeted by ransomware but lack the budget for enterprise EDR/XDR/MDR solutions. The Cyber Security Act 2024 (Act 854) now mandates:
- **6-hour incident reporting** with forensic evidence
- Continuous risk assessments and bi-annual audits
- Verifiable audit telemetry for NCII compliance

Traditional signature-based antivirus fails against zero-day ransomware, and manual threat detection is too slow to meet these regulatory deadlines.

## Solution

CAPT deploys **high-entropy canary (decoy) files** as digital tripwires across monitored directories. When ransomware attempts to encrypt these files, the system:

1. **Detects** the file modification via real-time monitoring
2. **Identifies** the responsible process (PID attribution)
3. **Validates** the threat using entropy analysis
4. **Terminates** the malicious process automatically
5. **Logs** the full incident for Act 854 compliance

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    ENDPOINT LAYER                       │
│                                                         │
│  Canary Management ──► Watchdog Detection Agent         │
│       Service              │                            │
│                            ▼                            │
│                    PID Attribution Module                │
│                            │                            │
│                            ▼                            │
│                    Entropy Analysis Engine               │
│                            │                            │
│                            ▼                            │
│                  Threat Classification Engine            │
│                            │                            │
│                            ▼                            │
│                 Process Termination Module               │
└────────────────────────┬────────────────────────────────┘
                         │ JSON payload (HTTP POST)
                         ▼
┌─────────────────────────────────────────────────────────┐
│                    BACKEND LAYER                        │
│                                                         │
│           Flask API Webhook ──► Firebase RT DB           │
└────────────────────────┬────────────────────────────────┘
                         │ Real-time sync
                         ▼
┌─────────────────────────────────────────────────────────┐
│                  PRESENTATION LAYER                     │
│                                                         │
│              React Dashboard (Vite + Tailwind)          │
│         Incident monitoring · Logs · Analytics          │
└─────────────────────────────────────────────────────────┘
```

## Tech Stack

| Component | Technology |
|---|---|
| Core framework | Python |
| File monitoring | Watchdog |
| Process management | psutil |
| Backend API | Flask |
| Database | Firebase Realtime Database |
| Dashboard | React + Vite + Tailwind CSS |
| Ransomware simulator | Custom Python script (see `AA_ransomware/`) |

## Project Structure

```
CAPT/
├── file_entropy_calculator.py   # Entropy analysis utility (Task 3)
├── directory_mapper.py          # Target directory mapper (Task 4)
├── canary_deployer.py           # Canary file deployer (Task 5)
├── watchdog_monitor.py          # Watchdog monitoring agent (Task 6)
├── canary_manifest.json         # Deployment manifest (auto-generated)
├── incident_log.jsonl           # Incident log (auto-generated)
├── test_sandbox/                # Auto-created sandbox directories
│   ├── Desktop/
│   │   ├── ~CAPT_canary.docx
│   │   ├── ~CAPT_canary.pdf
│   │   └── ~CAPT_canary.xlsx
│   └── Documents/
│       ├── ~CAPT_canary.docx
│       ├── ~CAPT_canary.pdf
│       └── ~CAPT_canary.xlsx
├── .gitignore
├── README.md
└── (modules to be developed per sprint plan)

AA_ransomware/                   # Ransomware simulator (separate repo)
├── rware_simulator.py           # Educational encryption simulator
├── confidential.docx            # Demo target file
└── .encryption_keys.json        # Generated RSA keys
```

## Current Progress

### Phase 1 — Foundation & Setup
- [x] **Task 1:** Python virtual environment setup (`venv`)
- [x] **Task 2:** Dummy document templates (`.docx`, `.pdf`, `.xlsx`)
- [x] **Task 3:** High-entropy random string generator (`file_entropy_calculator.py`)
- [x] **Task 4:** Target deployment directory mapper (`directory_mapper.py`)
- [x] **Task 5:** Canary (decoy) file generation & deployment (`canary_deployer.py`)

### Phase 2 — Detection Engine
- [x] **Task 6:** Watchdog file-system monitoring agent (`watchdog_monitor.py`)
- [x] **Task 7:** PID attribution module — integrated into `watchdog_monitor.py`
- [ ] **Task 8:** Entropy analysis & threat classification engine

### Phase 3 — Response & Termination
- [ ] **Task 9:** Automated process termination module
- [ ] **Task 10:** Ransomware simulator for controlled testing (`rware_simulator.py`)

### Phase 4 — Compliance & Logging
- [ ] **Task 11:** Act 854 compliance logging (6-hour incident report telemetry)
- [ ] **Task 12:** JSON incident payload generation

### Phase 5 — Backend & Dashboard
- [ ] **Task 13:** Flask API webhook (receive incident payloads)
- [ ] **Task 14:** Firebase Realtime Database integration
- [ ] **Task 15:** React dashboard (Vite + Tailwind CSS) — incident monitoring, logs & analytics

### Phase 6 — Testing & Evaluation
- [ ] **Task 16:** End-to-end VM integration testing
- [ ] **Task 17:** Detection accuracy & response time benchmarking
- [ ] **Task 18:** Final documentation & FYP report

## Quick Start

### Entropy Calculator
```bash
python file_entropy_calculator.py <file1> <file2> ...
```

### Ransomware Simulator (for testing)
```bash
# Encrypt demo files
python rware_simulator.py encrypt <target_directory>

# Decrypt demo files
python rware_simulator.py decrypt <target_directory>

# Check status
python rware_simulator.py status
```

## Objectives

1. Develop a behavioral ransomware detection and termination framework that automatically halts unauthorized encryption in real time
2. Utilize high-entropy decoy files as proactive tripwires that trigger containment protocols upon malicious access
3. Evaluate the framework's compliance with Malaysian Cyber Security Act 2024 (Act 854) by aligning automated telemetry with national incident reporting mandates

## Scope

**In-Scope:** Decoy file generation (.docx, .pdf, .xlsx), targeted directory monitoring, automated process termination, compliance logging, controlled VM testing with custom simulator.

**Out-of-Scope:** File recovery/decryption, antivirus replacement, real malware testing, system-level (Registry/System32) monitoring.

## References

- Malaysian Cyber Security Act 2024 (Act 854) — [NACSA](https://www.nacsa.gov.my/act854.php)
- NIST SP 800-61 Rev 3 — Incident Handling Guide
- NIST Cybersecurity Framework (CSF) 2.0
- ISO/IEC 27001:2022

## Author

**Danial Izzuddin bin Mohamad Shahir**
BSc (Hons) Computer Science (Cyber Security) — 3rd Year
Supervisor: Ts. Nafisah Misriya

## License

This project is for academic and research purposes only. Not intended for production deployment.
