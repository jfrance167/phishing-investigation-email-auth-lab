"""Repair disposable guest UTC clocks after host suspend, using host time and pinned SSH.

No NTP/external destination; each owned marker is checked before setting guest time.
This changes guest clocks, never timestamps in existing evidence. Rerun the runtime gate.
"""
import argparse
import json
import time
from pathlib import Path
from tools.lab import ssh
from tools.evidence import manifest


def sync(output):
    output.mkdir(parents=True,exist_ok=False)
    rows=[]
    for role in ('sender','receiver','relay'):
        if ssh(role,'cat /etc/peal-owned').stdout.strip()!=('PEAL-'+role).encode(): raise ValueError('Wrong guest')
        before=int(ssh(role,'date -u +%s').stdout)
        now=int(time.time())
        result=ssh(role,"date -u -s '@"+str(now)+"'; date -u +%s")
        rows.append({'role':role,'before_unix':before,'host_unix':now,'after':result.stdout.decode()})
    (output/'clock-recovery.json').write_text(json.dumps(rows,indent=2))
    (output/'SHA256.json').write_text(json.dumps(manifest(output),indent=2))


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    sync(parser.parse_args().output.resolve())
