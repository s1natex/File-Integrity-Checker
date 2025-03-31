#!/usr/bin/env python3

import argparse
import os
import hashlib
import json
from pathlib import Path

HASH_DB = Path.home() / ".integrity_hashes.json"

def compute_hash(file_path):
    sha256 = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256.update(chunk)
        return sha256.hexdigest()
    except Exception as e:
        print(f"Error reading {file_path}: {e}")
        return None

def load_hashes():
    if HASH_DB.exists():
        with open(HASH_DB, "r") as f:
            return json.load(f)
    return {}

def save_hashes(hashes):
    with open(HASH_DB, "w") as f:
        json.dump(hashes, f, indent=4)

def init_hashes(path):
    hashes = load_hashes()
    files = [Path(path)] if Path(path).is_file() else list(Path(path).rglob("*"))
    for file in files:
        if file.is_file():
            file_hash = compute_hash(file)
            if file_hash:
                hashes[str(file)] = file_hash
    save_hashes(hashes)
    print("Hashes stored successfully.")

def check_file(file_path):
    hashes = load_hashes()
    file_str = str(Path(file_path))
    if file_str not in hashes:
        print(f"{file_path}: No hash stored previously.")
        return
    current_hash = compute_hash(file_path)
    if current_hash != hashes[file_str]:
        print(f"{file_path}: Status: Modified (Hash mismatch)")
    else:
        print(f"{file_path}: Status: Unmodified")

def update_hash(file_path):
    hashes = load_hashes()
    file_str = str(Path(file_path))
    file_hash = compute_hash(file_path)
    if file_hash:
        hashes[file_str] = file_hash
        save_hashes(hashes)
        print(f"{file_path}: Hash updated successfully.")

def main():
    parser = argparse.ArgumentParser(description="Log File Integrity Checker")
    parser.add_argument("command", choices=["init", "check", "update"])
    parser.add_argument("path", help="Path to a log file or directory")

    args = parser.parse_args()

    if args.command == "init":
        init_hashes(args.path)
    elif args.command == "check":
        check_file(args.path)
    elif args.command == "update":
        update_hash(args.path)

if __name__ == "__main__":
    main()
