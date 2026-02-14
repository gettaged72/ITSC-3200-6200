# File Integrity Verification Tool (SHA-256)

A Python CLI tool that creates a baseline of **SHA-256 hashes** for every file in a directory, then verifies the directory later to detect:

- ✅ Modified files (hash mismatch)
- ✅ Deleted files
- ✅ Newly added files
- ✅ Renamed files (basic rename detection using matching hashes)

This is a simple example of **File Integrity Monitoring (FIM)** — a common cybersecurity technique used to detect tampering and unexpected changes.

---

## Features
- Recursively hashes all files in a target directory
- Saves results to `hash_table.json`
- Verifies current directory state against the saved baseline
- Skips hashing `hash_table.json` if it exists inside the target directory
- Normalizes file paths (absolute + normalized) for consistent comparisons

---

## Requirements
- Python 3.8+
- Standard library only (no external packages)

---

## Project Structure
- `Lab02HashingProgram.py` — main program (hashing + verification menu)
- `README.md` — project documentation
- `hash_table.json` — generated output (created after option 1)

---

## How It Works
1. Walks the directory using `os.walk()`
2. Hashes each file using SHA-256 in chunks (handles large files)
3. Stores baseline hashes in `hash_table.json`
4. Verification re-hashes files and compares results to baseline:
   - Same hash → valid
   - Different hash → modified
   - Missing from current scan → deleted
   - New in current scan → added
   - Same hash but different path → renamed (basic detection)

---

## Usage

### Run the program
```bash
python Lab02HashingProgram.py
