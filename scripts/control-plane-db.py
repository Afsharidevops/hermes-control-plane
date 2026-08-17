#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import sqlite3
import time
from pathlib import Path


def quick_check(path: Path) -> None:
    if not path.is_file():
        raise SystemExit(f"database file not found: {path}")
    conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        result = conn.execute("PRAGMA quick_check").fetchone()
    finally:
        conn.close()
    if not result or result[0] != "ok":
        raise SystemExit(f"SQLite integrity check failed for {path}: {result}")


def sqlite_backup(source: Path, destination: Path) -> None:
    source = source.resolve()
    destination = destination.resolve()
    quick_check(source)
    destination.parent.mkdir(parents=True, exist_ok=True)
    tmp = destination.with_name(destination.name + f".tmp-{os.getpid()}")
    if tmp.exists():
        tmp.unlink()
    src = sqlite3.connect(f"file:{source}?mode=ro", uri=True)
    dst = sqlite3.connect(tmp)
    try:
        src.backup(dst)
        dst.commit()
    finally:
        dst.close()
        src.close()
    quick_check(tmp)
    os.replace(tmp, destination)


def restore(source: Path, destination: Path) -> Path | None:
    source = source.resolve()
    destination = destination.resolve()
    quick_check(source)
    safety = None
    if destination.exists():
        stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
        safety = destination.with_name(destination.name + f".pre-restore-{stamp}")
        sqlite_backup(destination, safety)
    sqlite_backup(source, destination)
    quick_check(destination)
    return safety


def main() -> None:
    parser = argparse.ArgumentParser(description="Hermes Control Plane SQLite backup/restore helper")
    sub = parser.add_subparsers(dest="command", required=True)
    p_check = sub.add_parser("check")
    p_check.add_argument("path", type=Path)
    p_backup = sub.add_parser("backup")
    p_backup.add_argument("source", type=Path)
    p_backup.add_argument("destination", type=Path)
    p_restore = sub.add_parser("restore")
    p_restore.add_argument("source", type=Path)
    p_restore.add_argument("destination", type=Path)
    args = parser.parse_args()

    if args.command == "check":
        quick_check(args.path)
        print(f"ok {args.path}")
    elif args.command == "backup":
        sqlite_backup(args.source, args.destination)
        print(args.destination)
    else:
        safety = restore(args.source, args.destination)
        print(args.destination)
        if safety:
            print(f"pre_restore_backup={safety}")


if __name__ == "__main__":
    main()
