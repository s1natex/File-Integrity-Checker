import argparse
import hashlib
import json
import os
import sys
import tempfile
import hmac
from pathlib import Path
from fnmatch import fnmatch
from typing import Optional, List, Dict, Any, Tuple

DEFAULT_DB = Path.home() / ".integrity_hashes.json"
DEFAULT_PATTERN = "*.log"
SUPPORTED_ALGOS = {"sha256": hashlib.sha256, "blake2b": hashlib.blake2b}


def canonical(p: Path, follow_symlinks: bool) -> Path:
    try:
        return p.resolve(strict=True) if follow_symlinks else p.absolute()
    except FileNotFoundError:
        return p.absolute()


def is_symlink(p: Path) -> bool:
    try:
        return p.is_symlink()
    except Exception:
        return False


def compute_hash(file_path: Path, algo: str) -> Optional[str]:
    hasher = SUPPORTED_ALGOS[algo]()
    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                hasher.update(chunk)
        return hasher.hexdigest()
    except Exception as e:
        print(f"Error reading {file_path}: {e}", file=sys.stderr)
        return None


def load_db(db_path: Path) -> Dict[str, Any]:
    if not db_path.exists():
        return {"entries": {}, "meta": {"algo": "sha256"}, "signature": None}
    try:
        with open(db_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            if not isinstance(data, dict) or "entries" not in data:
                raise ValueError("Invalid DB structure")
            return data
    except Exception as e:
        print(f"Error loading DB {db_path}: {e}", file=sys.stderr)
        return {"entries": {}, "meta": {"algo": "sha256"}, "signature": None}


def hmac_sign(data_bytes: bytes, key: bytes, algo: str) -> str:
    # HMAC with same hash algo
    return hmac.new(key, data_bytes, SUPPORTED_ALGOS[algo]).hexdigest()


def stable_entries_bytes(entries: Dict[str, str]) -> bytes:
    return json.dumps(entries, sort_keys=True, separators=(",", ":")).encode("utf-8")


def verify_signature(
    db: Dict[str, Any], key_env: str = "INTEGRITY_KEY"
) -> Optional[bool]:
    key = os.environ.get(key_env)
    if not key or not db.get("signature"):
        return None
    algo = db.get("meta", {}).get("algo", "sha256")
    expected = db["signature"]
    actual = hmac_sign(stable_entries_bytes(db["entries"]), key.encode("utf-8"), algo)
    return hmac.compare_digest(expected, actual)


def save_db_atomic(db_path: Path, db: Dict[str, Any]) -> None:
    tmp: Optional[Path] = None
    try:
        db_path.parent.mkdir(parents=True, exist_ok=True)
        key = os.environ.get("INTEGRITY_KEY")
        if key:
            algo = db.get("meta", {}).get("algo", "sha256")
            db["signature"] = hmac_sign(
                stable_entries_bytes(db["entries"]), key.encode("utf-8"), algo
            )
        tmp_fd, tmp_name = tempfile.mkstemp(
            prefix=".integrity.", dir=str(db_path.parent)
        )
        tmp = Path(tmp_name)
        with os.fdopen(tmp_fd, "w", encoding="utf-8") as f:
            json.dump(db, f, indent=2, sort_keys=True)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, db_path)
        os.chmod(db_path, 0o600)
    finally:
        if tmp and tmp.exists():
            try:
                tmp.unlink()
            except Exception:
                pass


def iter_files(root: Path, pattern: str, follow_symlinks: bool) -> List[Path]:
    root = root if root.is_file() else root
    if root.is_file():
        return [root]
    results: List[Path] = []
    for p in root.rglob("*"):
        try:
            if p.is_file():
                if pattern == "*" or fnmatch(p.name, pattern):
                    results.append(p)
        except PermissionError:
            print(f"Permission denied: {p}", file=sys.stderr)
        except Exception as e:
            print(f"Skipping {p}: {e}", file=sys.stderr)
    return results


def cmd_init(
    path: Path,
    db_path: Path,
    pattern: str,
    algo: str,
    follow_symlinks: bool,
    include_symlinks: bool,
) -> None:
    db = load_db(db_path)
    db["meta"]["algo"] = algo
    paths = iter_files(path, pattern, follow_symlinks)
    skip = canonical(db_path, follow_symlinks=False)
    count = 0
    for p in paths:
        if not include_symlinks and is_symlink(p):
            continue
        cpath = canonical(p, follow_symlinks)
        if cpath == skip:
            continue
        h = compute_hash(cpath, algo)
        if h:
            db["entries"][str(cpath)] = h
            count += 1
    save_db_atomic(db_path, db)
    print(f"Hashes stored successfully: {count} entr{'y' if count == 1 else 'ies'}.")


def _check_one(
    p: Path, db: Dict[str, Any], algo: str, follow_symlinks: bool
) -> Tuple[str, str, Optional[str]]:
    cpath = canonical(p, follow_symlinks)
    current = compute_hash(cpath, algo)
    if current is None:
        return ("error", str(cpath), "Read error")
    stored = db["entries"].get(str(cpath))
    if stored is None:
        return ("new", str(cpath), "No hash stored")
    return ("modified" if current != stored else "ok", str(cpath), None)


def cmd_check(
    path: Path,
    db_path: Path,
    pattern: str,
    json_out: bool,
    follow_symlinks: bool,
    include_symlinks: bool,
) -> None:
    db = load_db(db_path)
    sig_ok = verify_signature(db)
    if sig_ok is False:
        print(
            "WARNING: Hash DB signature verification FAILED. DB may be tampered.",
            file=sys.stderr,
        )

    algo = db.get("meta", {}).get("algo", "sha256")
    paths = iter_files(path, pattern, follow_symlinks)
    results: List[Dict[str, Any]] = []

    for p in paths:
        if not include_symlinks and is_symlink(p):
            continue
        status, cpath, msg = _check_one(p, db, algo, follow_symlinks)
        results.append({"path": cpath, "status": status, "message": msg})

    root = canonical(path, follow_symlinks=False)
    missing: List[Dict[str, str]] = []
    for ep in db["entries"].keys():
        if str(ep).startswith(str(root)):
            if not Path(ep).exists():
                missing.append(
                    {
                        "path": ep,
                        "status": "missing",
                        "message": "Previously tracked, now missing",
                    }
                )

    results.extend(missing)

    modified = [r for r in results if r["status"] == "modified"]
    new = [r for r in results if r["status"] == "new"]
    missing_list = [r for r in results if r["status"] == "missing"]
    errors = [r for r in results if r["status"] == "error"]

    summary = {
        "total_checked": len(
            [r for r in results if r["status"] in ("ok", "modified", "new", "error")]
        ),
        "ok": len([r for r in results if r["status"] == "ok"]),
        "modified": len(modified),
        "missing": len(missing_list),
        "new": len(new),
        "errors": len(errors),
        "db_signature_verified": (
            (True if sig_ok else False) if sig_ok is not None else None
        ),
    }

    if json_out:
        print(json.dumps({"results": results, "summary": summary}, indent=2))
    else:
        for r in results:
            status = r["status"]
            if status == "ok":
                print(f"{r['path']}: Status: Unmodified")
            elif status == "modified":
                print(f"{r['path']}: Status: MODIFIED (hash mismatch)")
            elif status == "missing":
                print(f"{r['path']}: Status: MISSING (tracked but not found)")
            elif status == "new":
                print(f"{r['path']}: Status: NEW (no stored hash)")
            elif status == "error":
                print(f"{r['path']}: Status: ERROR ({r['message']})")
        print(
            f"\nSummary: ok={summary['ok']} modified={summary['modified']} "
            f"missing={summary['missing']} new={summary['new']} errors={summary['errors']}"
            + (
                ""
                if summary["db_signature_verified"] is None
                else f" | DB signature ok={summary['db_signature_verified']}"
            )
        )

    exit_code = 0
    if errors:
        exit_code = 1
    if summary["modified"] or summary["missing"]:
        exit_code = max(exit_code, 2)
    if sig_ok is False:
        exit_code = max(exit_code, 3)
    sys.exit(exit_code)


def cmd_update(
    path: Path,
    db_path: Path,
    pattern: str,
    follow_symlinks: bool,
    include_symlinks: bool,
) -> None:
    db = load_db(db_path)
    algo = db.get("meta", {}).get("algo", "sha256")
    paths = iter_files(path, pattern, follow_symlinks)
    updated = 0
    for p in paths:
        if not include_symlinks and is_symlink(p):
            continue
        cpath = canonical(p, follow_symlinks)
        h = compute_hash(cpath, algo)
        if h:
            db["entries"][str(cpath)] = h
            updated += 1
    save_db_atomic(db_path, db)
    print(f"{updated} entr{'y' if updated == 1 else 'ies'} updated successfully.")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Log File Integrity Checker")
    sub = parser.add_subparsers(dest="command", required=True)

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("path", help="Path to a log file or directory")
    common.add_argument(
        "--db", default=str(DEFAULT_DB), help=f"Path to hash DB (default: {DEFAULT_DB})"
    )
    common.add_argument(
        "--pattern",
        default=DEFAULT_PATTERN,
        help=f"Filename glob when PATH is a directory (default: {DEFAULT_PATTERN})",
    )
    common.add_argument(
        "--follow-symlinks", action="store_true", help="Resolve symlinks (default: off)"
    )
    common.add_argument(
        "--include-symlinks",
        action="store_true",
        help="Include symlinked files in scans (default: off)",
    )

    p_init = sub.add_parser("init", parents=[common], help="Initialize hashes")
    p_init.add_argument(
        "--algo",
        choices=SUPPORTED_ALGOS.keys(),
        default="sha256",
        help="Hash algorithm",
    )

    p_check = sub.add_parser("check", parents=[common], help="Check hashes")
    p_check.add_argument(
        "--json", action="store_true", help="JSON output (results + summary)"
    )

    # create the 'update' subparser without binding to a variable (avoids ruff F841)
    sub.add_parser("update", parents=[common], help="Update stored hash(es)")

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    db_path = Path(args.db)
    path = Path(args.path)

    if args.command == "init":
        cmd_init(
            path,
            db_path,
            args.pattern,
            args.algo,
            args.follow_symlinks,
            args.include_symlinks,
        )
    elif args.command == "check":
        cmd_check(
            path,
            db_path,
            args.pattern,
            args.json,
            args.follow_symlinks,
            args.include_symlinks,
        )
    elif args.command == "update":
        cmd_update(
            path, db_path, args.pattern, args.follow_symlinks, args.include_symlinks
        )


if __name__ == "__main__":
    main()
