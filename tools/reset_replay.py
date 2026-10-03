"""Preserve evidence, reset fixed marked guests' config/caches, replay representative cases.

Retains keys, Redis reporting data and Mailpit capture. Deletes only individually exported
synthetic queue entries, never a whole queue, VM, disk, report database or host resource.
"""
import argparse
import hashlib
import json
import re
from pathlib import Path
from tools.lab import ROOT,ssh,upload,run_case,ready
from tools.evidence import manifest,verify
from tools.queue_ledger import queue_ledger,authorized_queue


def reset_replay(output):
    output.mkdir(parents=True,exist_ok=False)
    checked=[]
    for path in (ROOT/'evidence').rglob('SHA256.json'):
        verify(path.parent)
        checked.append(path.parent.relative_to(ROOT).as_posix())
    (output/'verified-before-reset.json').write_text(json.dumps(checked,indent=2))
    ready(output/'gate-before',True)
    ledger=queue_ledger(ROOT/'evidence')
    for role in ('sender','receiver','relay'):
        if ssh(role,'cat /etc/peal-owned').stdout.strip()!=('PEAL-'+role).encode(): raise ValueError('Wrong guest')
        snapshot=ssh(role,'postconf -n; postqueue -j; cat /etc/bind/peal.test.zone 2>/dev/null || true').stdout
        (output/(role+'-before.txt')).write_bytes(snapshot)
        for line in ssh(role,'postqueue -j').stdout.splitlines():
            row=json.loads(line); qid=row['queue_id']
            if not re.fullmatch('[A-Za-z0-9]{5,30}',qid): raise ValueError('Unsafe queue ID')
            raw=ssh(role,'postcat -bhq '+qid).stdout
            saved=output/(role+'-'+qid+'.eml'); saved.write_bytes(raw)
            (output/(role+'-'+qid+'-export.json')).write_text(json.dumps({'role':role,'queue_id':qid,
                'sha256':hashlib.sha256(raw).hexdigest(),'authorized':authorized_queue(role,qid,raw,ledger)},indent=2))
            # A copyable header alone never authorizes deletion; require queue/run linkage to verified exports.
            if authorized_queue(role,qid,raw,ledger):
                if ssh(role,'postcat -bhq '+qid).stdout!=raw: raise ValueError('Queue changed after export; retain and review')
                (output/(role+'-'+qid+'-remove.txt')).write_bytes(ssh(role,'postsuper -d '+qid).stdout)
            else:
                (output/(role+'-'+qid+'-retained.txt')).write_text('No verified queue/run collection linkage: retained, not deleted.')
    # Capture DB is retained unchanged. Restart authentication services to clear their DNS caches.
    for role in ('sender','receiver'):
        upload(role,ROOT/'tools/configure-mail.sh','/opt/peal/configure-mail.sh')
        (output/(role+'-reset.txt')).write_bytes(ssh(role,'sh /opt/peal/configure-mail.sh '+role).stdout)
    ssh('sender',"postconf -e 'defer_transports = smtp'; postfix reload")
    upload('receiver',ROOT/'tools/configure-dns-mailpit.sh','/opt/peal/configure-dns-mailpit.sh')
    (output/'dns-reset.txt').write_bytes(ssh('receiver','sh /opt/peal/configure-dns-mailpit.sh').stdout)
    upload('relay',ROOT/'tools/relay_filter.py','/opt/peal/relay_filter.py')
    upload('relay',ROOT/'tools/configure-relay.sh','/opt/peal/configure-relay.sh')
    (output/'relay-reset.txt').write_bytes(ssh('relay','sh /opt/peal/configure-relay.sh').stdout)
    matrix=json.loads((ROOT/'scenarios/matrix.json').read_text())
    results=[]
    for id_ in ('S01','S02','S05a','S07q','S07x','S09f','S09m','S10','S11'):
        case=next(c for c in matrix if c['id']==id_)
        results.append(run_case(case,output/id_))
    (output/'replay-summary.json').write_text(json.dumps(results,indent=2))
    (output/'SHA256.json').write_text(json.dumps(manifest(output),indent=2))
    if not all(r['expected_match'] for r in results): raise ValueError('Replay semantic assertion failed')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    reset_replay(parser.parse_args().output.resolve())
