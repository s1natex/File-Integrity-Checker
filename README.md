# File Integrity Checker

Verify the integrity of application log files to detect tampering.  
This tool computes and stores cryptographic hashes of log files, then checks them later to detect if anything has been modified, deleted, or newly added.
CI with linting and smoke tests, uncomment to Publish to PyPI (tagged releases)

[![CI](https://github.com/s1natex/File-Integrity-Checker/actions/workflows/CI.yaml/badge.svg)](https://github.com/s1natex/File-Integrity-Checker/actions/workflows/CI.yml)

# [Project Page](https://roadmap.sh/projects/file-integrity-checker)

---

## Features

- **SHA256 / BLAKE2b hashing** – secure, fast file fingerprinting  
- **Directory or single file support** – works on one log or an entire folder  
- **Detects**:
  - Modified files (hash mismatch)  
  - Missing files (previously tracked but now gone)  
  - New files (not previously tracked)  
- **Machine-readable JSON output** (`--json`) for automation / SIEM  
- **Configurable filename pattern** (`--pattern "*.log"`)  
- **Optional DB signing with HMAC** (`INTEGRITY_KEY` env var) to detect DB tampering  
- **Exit codes for automation**:  
  - `0` → all good  
  - `1` → errors (I/O, permissions, etc.)  
  - `2` → modified or missing files  
  - `3` → DB signature failed  
- **Safe JSON DB** stored at `~/.integrity_hashes.json` (by default)  
- **Atomic DB writes** (no corruption if interrupted)  
- **Cross-platform**: Linux, Windows, macOS  

---

## integrity-check commands
```
integrity-check --help

integrity-check init /var/log/app --pattern "*.log"

integrity-check check /var/log/app --pattern "*.log"

integrity-check check /var/log/app --json > /tmp/integrity-report.json

integrity-check update /var/log/app/app.log

integrity-check check C:\path\to\logs --pattern "*.log"

integrity-check update C:\path\to\logs\app.log

integrity-check check C:\path\to\logs >> C:\Users\<YourName>\integrity-check.log 2>&1
```

## Installation (Linux)

### 1. Clone and build
```bash
git clone https://github.com/s1natex/File-Integrity-Checker
cd file-integrity-checker

sudo apt update
sudo apt install -y python3-pip python3-venv

python3 -m pip install --upgrade pip
python3 -m pip install --upgrade build pipx
python3 -m pipx ensurepath

# make sure current shell sees ~/.local/bin
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc

python3 -m build
```

### 2. Install with pipx
```bash
pipx install ./dist/file_integrity_checker-0.1.0-py3-none-any.whl
```

### 3. Verify
```bash
integrity-check --help
```

---

## Installation (Windows)

### 1. Build
```powershell
git clone https://github.com/yourusername/file-integrity-checker.git
cd file-integrity-checker
py -m pip install --upgrade build pipx
py -m build
```

### 2. Install with pipx
```powershell
pipx install .\dist\file_integrity_checker-0.1.0-py3-none-any.whl
```

### 3. Verify
```powershell
integrity-check --help
```

---

## Usage Examples

### Initialize baseline
```bash
integrity-check init /var/log/app --pattern "*.log"
```

### Check integrity
```bash
integrity-check check /var/log/app --pattern "*.log"
```

Example output:
```
/var/log/app/app.log: Status: Unmodified
/var/log/app/error.log: Status: MODIFIED (hash mismatch)
/var/log/app/old.log: Status: MISSING (tracked but not found)

Summary: ok=1 modified=1 missing=1 new=0 errors=0
```

### JSON output
```bash
integrity-check check /var/log/app --json > /tmp/integrity-report.json
```

### Update hashes
```bash
integrity-check update /var/log/app/app.log
```

---

## Linux Scheduling

### Linux (cron)
```
*/5 * * * * integrity-check check /var/log/app --pattern "*.log" >> /var/log/integrity-check.log 2>&1
```

### Windows (Task Scheduler)
```
integrity-check check C:\path\to\logs >> C:\Users\<Name>\integrity-check.log 2>&1
```

---

## Signed DB

Linux:
```bash
export INTEGRITY_KEY="a-strong-secret-key"
```

Windows (PowerShell):
```powershell
setx INTEGRITY_KEY "a-strong-secret-key"
```

---

## Exit Codes

| Code | Meaning                         |
|------|---------------------------------|
| 0    | All good                        |
| 1    | Errors (permissions, I/O, etc.) |
| 2    | Modified or missing files       |
| 3    | DB signature verification failed |
