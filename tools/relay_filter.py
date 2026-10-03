"""Bounded synthetic forwarding filter; non-root pipe, local-only SMTP reinjection.

Message headers select only two harmless transformations, never a path or command.
Postfix supplies the envelope separately. Preserve both byte streams before forwarding.
"""
import hashlib
import json
import re
import smtplib
import sys
from email import policy
from email.parser import BytesParser
from pathlib import Path

MAX_BYTES=2_097_152


def transform(raw):
    if len(raw)>MAX_BYTES: raise ValueError('Message too large')
    msg=BytesParser(policy=policy.default).parsebytes(raw)
    scenario=str(msg.get('X-Lab-Scenario',''))
    run_id=str(msg.get('X-Lab-Run',''))
    if scenario not in ('S09f','S09m') or not re.fullmatch('[a-f0-9]{32}',run_id):
        raise ValueError('Not a supported synthetic forwarding run')
    changed=raw if scenario=='S09f' else raw+b'\nHarmless fictional mailing-list footer.\n'
    return scenario,run_id,changed


def main():
    sender,recipient=sys.argv[1:]
    if sender!='analyst@sender.test' or recipient!='analyst@recipient.test':
        raise ValueError('Envelope outside fixed lab identities')
    raw=sys.stdin.buffer.read(MAX_BYTES+1)
    scenario,run_id,changed=transform(raw)
    dest=Path('/var/lib/peal-relay')/run_id
    dest.mkdir(mode=0o700,exist_ok=False)
    (dest/'before.eml').write_bytes(raw)
    (dest/'after.eml').write_bytes(changed)
    with smtplib.SMTP('127.0.0.1',10026,timeout=15) as client:
        refused=client.sendmail(sender,[recipient],changed)
        if refused: raise ValueError('Reinjection refused')
    (dest/'forward.json').write_text(json.dumps({'scenario':scenario,'run_id':run_id,
        'envelope_from':sender,'envelope_to':recipient,'reinjected':True,
        'before_sha256':hashlib.sha256(raw).hexdigest(),'after_sha256':hashlib.sha256(changed).hexdigest()},indent=2))


if __name__=='__main__': main()
