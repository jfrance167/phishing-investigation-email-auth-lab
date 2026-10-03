"""Generate only disposable lab2 key, publish overlap, test retirement warm/cold, restore DNS."""
import argparse
import json
from pathlib import Path
from tools.lab import ROOT,ssh,upload,run_case,ready
from tools.evidence import manifest


def main(output):
    output.mkdir(exist_ok=False,parents=True)
    ready(output/'gate-before')
    base=ssh('receiver','cat /etc/bind/peal.test.zone').stdout.decode()
    (output/'before.zone').write_text(base,newline='\n')
    try:
        result=ssh('sender',"set -eu; test -f /var/lib/rspamd/dkim/sender.test.lab2.key || rspamadm dkim_keygen -s lab2 -d sender.test -b 2048 -k /var/lib/rspamd/dkim/sender.test.lab2.key > /opt/peal/sender.test.lab2.dns; chown _rspamd:_rspamd /var/lib/rspamd/dkim/sender.test.lab2.key; chmod 600 /var/lib/rspamd/dkim/sender.test.lab2.key; cat /opt/peal/sender.test.lab2.dns")
        (output/'lab2-public.dns').write_bytes(result.stdout)
        zone='\n'.join(x for x in base.splitlines() if x.strip()).replace('$TTL 30','$TTL 120')+'\n$ORIGIN sender.test.\n'+result.stdout.decode()
        (output/'overlap.zone').write_text(zone,newline='\n')
        upload('receiver',output/'overlap.zone','/opt/peal/rotation.zone')
        ssh('receiver','named-checkzone test /opt/peal/rotation.zone && cp /opt/peal/rotation.zone /etc/bind/peal.test.zone && systemctl restart named rspamd')
        cases=json.loads((ROOT/'scenarios/matrix.json').read_text())
        observed=[]
        for case in [c for id_ in ('S12b','S12a','S12c','S12d') for c in cases if c['id']==id_]:
            observed.append(run_case(case,output/case['id']))
        (output/'summary.json').write_text(json.dumps(observed,indent=2))
    finally:
        upload('receiver',output/'before.zone','/opt/peal/rotation-restore.zone')
        ssh('receiver','cp /opt/peal/rotation-restore.zone /etc/bind/peal.test.zone && systemctl restart named rspamd')
        ssh('sender',"sed -i 's/^selector = .*/selector = \"lab1\";/' /etc/rspamd/local.d/dkim_signing.conf && systemctl restart rspamd")
    (output/'SHA256.json').write_text(json.dumps(manifest(output),indent=2))
    require_rotation_passes(observed)


def require_rotation_passes(observed):
    if len(observed)!=4 or not all(row.get('expected_match') is True for row in observed):
        raise ValueError('Rotation outcome mismatch; inspect preserved summary and evidence')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    main(parser.parse_args().output.resolve())
