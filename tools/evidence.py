"""Bounded offline evidence integrity and claim/provenance separation.

Hash manifests detect changes, not malicious rewriting by a trusted administrator.
Receiver JSON is trusted only after a reviewer validates its controlled collection path.
"""
import argparse
import hashlib
import json
import re
from email import policy
from email.parser import BytesParser
from pathlib import Path

MAX_BYTES = 2_097_152
AUTH_RE = re.compile(r'\b(spf|dkim|dmarc)\s*=\s*([a-z]+)', re.I)


def bounded_bytes(path):
    if path.stat().st_size > MAX_BYTES:
        raise ValueError('Evidence exceeds 2 MiB parser limit')
    return path.read_bytes()


def claims(path):
    """Return all submitted authentication claims; never promote a header to trusted evidence."""
    message = BytesParser(policy=policy.default).parsebytes(bounded_bytes(path))
    return [{'header':str(value), 'trust':'unverified-submitted-claim',
             'parsed':AUTH_RE.findall(str(value))}
            for value in message.get_all('Authentication-Results', [])]


def summarize_receiver(path):
    """Summarize established implementation symbols, keeping the evidence source explicit."""
    record = json.loads(bounded_bytes(path))
    if not isinstance(record,dict): raise ValueError('Receiver record must be an object')
    if record.get('source') != 'receiver-rspamd-milter' or not isinstance(record.get('queue_id'),str) or not re.fullmatch(r'[A-Za-z0-9]{5,30}', record['queue_id']):
        raise ValueError('Not a valid receiver record')
    for name in ('ip','helo','action'):
        if not isinstance(record.get(name),str): raise ValueError('Missing/malformed receiver '+name)
    for name in ('symbols','envelope_from','envelope_to'):
        if not isinstance(record.get(name),list) or len(record[name])>4096 or not all(isinstance(item,dict) for item in record[name]):
            raise ValueError('Malformed receiver '+name)
    if any(not isinstance(item.get('name'),str) or not isinstance(item.get('options',[]),list) for item in record['symbols']):
        raise ValueError('Malformed receiver symbol')
    symbols = {item['name']:item.get('options',[]) for item in record['symbols']}
    def choose(candidates):
        found = [result for symbol,result in candidates if symbol in symbols]
        return found[0] if len(set(found)) == 1 else ('conflicting' if found else 'unknown')
    return {'queue_id':record['queue_id'], 'ip':record['ip'], 'helo':record['helo'],
            'envelope_from':record['envelope_from'], 'envelope_to':record['envelope_to'],
            'scenario_claim':record.get('scenario_claim'), 'recommended_action':record['action'],
            'spf':choose([('R_SPF_ALLOW','pass'),('R_SPF_FAIL','fail'),('R_SPF_SOFTFAIL','softfail'),
                          ('R_SPF_DNSFAIL','temperror'),('R_SPF_PERMFAIL','permerror'),('R_SPF_NA','none')]),
            'dkim':choose([('R_DKIM_ALLOW','pass'),('R_DKIM_REJECT','fail'),('R_DKIM_TEMPFAIL','temperror'),
                           ('R_DKIM_PERMFAIL','permerror'),('R_DKIM_NA','none')]),
            'dmarc':choose([('DMARC_POLICY_ALLOW','pass'),('DMARC_POLICY_REJECT','fail'),
                            ('DMARC_POLICY_QUARANTINE','fail'),('DMARC_POLICY_SOFTFAIL','fail'),
                            ('DMARC_DNSFAIL','temperror'),('DMARC_BAD_POLICY','permerror'),('DMARC_NA','none')]),
            'symbols':symbols,
            'provenance_requirement':'Validate pinned-SSH receiver collection and queue-correlated SMTP/log/disposition evidence; this JSON cannot establish its own authenticity.'}


def manifest(directory):
    root = directory.resolve()
    files = {}
    for path in sorted(root.rglob('*')):
        if path.is_symlink():
            raise ValueError('Symlink in evidence bundle')
        if path.is_file() and path.name != 'SHA256.json':
            files[path.relative_to(root).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    return files


def verify(directory):
    expected = json.loads((directory / 'SHA256.json').read_text())
    if expected != manifest(directory):
        raise ValueError('Evidence file set or hashes changed')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=['claims','receiver','manifest','verify'])
    parser.add_argument('path',type=Path)
    args = parser.parse_args()
    if args.operation == 'claims': result = claims(args.path)
    elif args.operation == 'receiver': result = summarize_receiver(args.path)
    elif args.operation == 'manifest':
        dest = args.path / 'SHA256.json'
        with dest.open('x',encoding='utf-8') as stream:
            json.dump(manifest(args.path),stream,indent=2)
        result = {'manifest':str(dest)}
    else:
        verify(args.path)
        result = {'integrity':'passed'}
    print(json.dumps(result,indent=2))


if __name__ == '__main__':
    main()
