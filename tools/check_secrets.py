"""Bounded high-confidence local tracked-file/history secret check; never print matching values.

This pattern check is not a full commercial scanner or proof of absence. Private lab artifacts
must stay ignored. The Git history check covers reachable local commits, without rewriting them.
"""
import json
import re
import shutil
import subprocess  # nosec B404 # Fixed Git read-only commands; no shell or remote operations.
from pathlib import Path

GIT=shutil.which('git')
ROOT=Path(__file__).resolve().parents[1]
PATTERNS=[br'-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----',
    br'\bgh[pousr]_[A-Za-z0-9]{30,}\b',br'\bgithub_pat_[A-Za-z0-9_]{50,}\b',
    br'\bAKIA[0-9A-Z]{16}\b',br'\bsk-[A-Za-z0-9]{30,}\b']


def git(*args):
    if not GIT: raise ValueError('Git unavailable')
    return subprocess.check_output([GIT,*args],cwd=ROOT,timeout=30)  # nosec B603 # Absolute discovered Git executable with fixed read-only argv, locally obtained validated object IDs.


def scan():
    root=Path(__file__).resolve().parents[1]
    issues=[]
    paths=[p for p in git('ls-files','-z').decode().split('\x00') if p]
    for path in paths:
        if path.startswith('.private/') or Path(path).suffix.lower() in ('.key','.pem','.vdi','.iso'):
            issues.append({'path':path,'issue':'private artifact tracked'})
        content=(root/path).read_bytes()
        if any(re.search(pattern,content) for pattern in PATTERNS):
            issues.append({'path':path,'issue':'possible secret pattern; value withheld'})
    commits=git('rev-list','--all').decode().splitlines()
    objects={}
    for commit in commits:
        if not re.fullmatch('[a-f0-9]{40,64}',commit): raise ValueError('Invalid Git object')
        for line in git('ls-tree','-r',commit).decode().splitlines():
            entry,path=line.split('\t',1)
            kind,oid=entry.split()[1:]
            if kind=='blob': objects[oid]=path
    for oid,path in objects.items():
        content=git('cat-file','blob',oid)
        if any(re.search(pattern,content) for pattern in PATTERNS):
            issues.append({'path':path,'issue':'history possible secret; value withheld'})
    return {'tracked_files':len(paths),'reachable_commits':len(commits),'issues':issues,
        'limit':'High-confidence pattern and private-artifact check; manual review remains required.'}


if __name__=='__main__':
    result=scan()
    print(json.dumps(result,indent=2))
    raise SystemExit(1 if result['issues'] else 0)
