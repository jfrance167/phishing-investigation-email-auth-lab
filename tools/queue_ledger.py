"""Authorize individual queue cleanup from verified controlled collections, never headers alone.

Local manifests detect changes; their trusted provenance still depends on controlled collection.
Unknown, legacy/nonced-less or ambiguous messages are retained. No destructive calls here.
"""
import json
import re
from email import policy
from email.parser import BytesParser
from tools.evidence import verify,bounded_bytes,MAX_BYTES


def queue_ledger(root):
    ledger={}
    for path in root.rglob('SHA256.json'):
        bundle=path.parent
        if not all((bundle/name).is_file() for name in ('expected.json','run.json','receiver.json')): continue
        verify(bundle)
        case=json.loads(bounded_bytes(bundle/'expected.json'))
        run=json.loads(bounded_bytes(bundle/'run.json'))
        record=json.loads(bounded_bytes(bundle/'receiver.json'))
        scenario=case.get('id'); nonce=run.get('run_id'); qid=record.get('queue_id')
        if not isinstance(scenario,str) or not re.fullmatch(r'S[0-9]{2}[a-z]?',scenario): continue
        if not isinstance(nonce,str) or not re.fullmatch(r'[a-f0-9]{32}',nonce): continue
        if record.get('source')!='receiver-rspamd-milter' or record.get('run_claim')!=nonce or record.get('scenario_claim')!=scenario: continue
        if isinstance(qid,str) and re.fullmatch(r'[A-Za-z0-9]{5,30}',qid):
            ledger.setdefault(('receiver',qid),set()).add((scenario,nonce))
        sender=bundle/'sender-smtp.txt'
        if sender.is_file():
            matches=re.findall(rb'queued as ([A-Za-z0-9]{5,30})',bounded_bytes(sender))
            if len(matches)==1:
                ledger.setdefault(('sender',matches[0].decode()),set()).add((scenario,nonce))
    return ledger


def authorized_queue(role,qid,raw,ledger):
    if len(raw)>MAX_BYTES: return False
    message=BytesParser(policy=policy.default).parsebytes(raw)
    scenarios=message.get_all('X-Lab-Scenario',[])
    nonces=message.get_all('X-Lab-Run',[])
    if len(scenarios)!=1 or len(nonces)!=1: return False
    return (str(scenarios[0]),str(nonces[0])) in ledger.get((role,qid),set())
