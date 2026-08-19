#!/usr/bin/env python3
from __future__ import annotations
import argparse, hashlib, json, shutil, sqlite3, time
from pathlib import Path

def integrity(path: Path) -> None:
    with sqlite3.connect(path) as conn:
        result = conn.execute('PRAGMA integrity_check').fetchone()[0]
    if result != 'ok':
        raise SystemExit(f'integrity check failed for {path}: {result}')

def sha256(path: Path) -> str:
    h=hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda:f.read(1024*1024), b''): h.update(chunk)
    return h.hexdigest()

def backup(src: Path, dst: Path) -> None:
    dst.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(src) as source, sqlite3.connect(dst) as target:
        source.backup(target)
    integrity(dst)
    print(json.dumps({'status':'ok','backup':str(dst),'sha256':sha256(dst)}, sort_keys=True))

def restore(src: Path, dst: Path) -> None:
    integrity(src)
    safety = dst.with_name(dst.name + f'.pre-restore-{int(time.time())}.bak')
    if dst.exists():
        backup(dst, safety)
    tmp = dst.with_name(dst.name + '.restore-tmp')
    shutil.copy2(src, tmp)
    integrity(tmp)
    tmp.replace(dst)
    integrity(dst)
    print(json.dumps({'status':'ok','restored':str(dst),'source_sha256':sha256(src),'safety_backup':str(safety) if safety.exists() else None}, sort_keys=True))

def main():
    ap=argparse.ArgumentParser(description='Hermes Control Plane SQLite backup/restore')
    sub=ap.add_subparsers(dest='cmd', required=True)
    b=sub.add_parser('backup'); b.add_argument('database', type=Path); b.add_argument('output', type=Path)
    r=sub.add_parser('restore'); r.add_argument('backup', type=Path); r.add_argument('database', type=Path)
    args=ap.parse_args()
    backup(args.database,args.output) if args.cmd=='backup' else restore(args.backup,args.database)
if __name__=='__main__': main()
