# File Integrity Verification Tool (SHA-256)

A lightweight Python CLI tool that generates and verifies **SHA-256 hashes** for all files in a directory to detect:
- ✅ **Modified files** (hash mismatch)
- ✅ **Deleted files**
- ✅ **Newly added files**
- ✅ **Renamed files** (basic rename detection using matching hashes)

This is a simple example of **file integrity monitoring**, a common cybersecurity technique used to detect tampering and unexpected changes on systems.

---

## Why this matters (Security context)
Hashing is used in cybersecurity to verify integrity and detect unauthorized changes. Tools like this help support:
- File integrity monitoring (FIM)
- Incident response validation (has anything changed?)
- Detecting tampering on sensitive directories
- Compliance / auditing checks

---

## Features
- **Generate a baseline hash table** for a target directory
- **Verify current files** against the stored baseline
- Outputs results for:
  - Valid/invalid hashes
  - Deleted files
  - Added files
  - Renamed files (same hash, different path)
- Stores results in a JSON file: `hash_table.json`

---

## Requirements
- Python 3.8+ (works with standard library only)

No external libraries needed.

---

## How it works
1. The program walks a directory recursively (`os.walk`)
2. Each file is hashed using **SHA-256**
3. Hashes are stored in `hash_table.json`
4. Verification re-hashes files and compares results to the baseline

---

## Usage

### 1) Run the program
```bash
python main.py
