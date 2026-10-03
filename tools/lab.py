"""Run fixed synthetic matrix cases over pinned SSH; preserve evidence before queue removal.

Prerequisite: Test-LabReady.ps1 passes immediately before each case. No browser rendering.
Only fixed guest addresses and scenario IDs from the reviewed manifest are accepted.
"""
import argparse
from datetime import datetime,timezone
from email import policy
from email.parser import BytesParser
import json
import re
import shlex
import shutil
import subprocess  # nosec B404 # Reviewed fixed executables; no local shell invocation.
import sys
import time
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from tools.evidence import summarize_receiver, manifest,bounded_bytes

SSH = Path('C:/Windows/System32/OpenSSH/ssh.exe')
SCP = Path('C:/Windows/System32/OpenSSH/scp.exe')
POWERSHELL = Path(shutil.which('pwsh') or 'C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe').resolve()
ADDRESSES = {'sender':'192.168.56.50','receiver':'192.168.56.51','relay':'192.168.56.52'}
OPTIONS = ['-i',str(ROOT/'.private/id_ed25519'),'-o','BatchMode=yes','-o','ConnectTimeout=5',
           '-o','StrictHostKeyChecking=yes','-o',f'UserKnownHostsFile="{ROOT / ".private/known_hosts"}"']


def ssh(role, command, check=True):
    return subprocess.run([str(SSH),*OPTIONS,'root@'+ADDRESSES[role],command],capture_output=True,timeout=40,check=check)  # nosec B603 # Remote commands are fixed code with allowlisted scenario fields and validated queue IDs.


def upload(role, local, remote):
    subprocess.run([str(SCP),*OPTIONS,str(local),'root@'+ADDRESSES[role]+':'+remote],check=True,timeout=40)  # nosec B603 # Fixed SCP executable, pinned lab host, fixed guest destination; local path is a single argv value.


def download(role, remote, local):
    subprocess.run([str(SCP),*OPTIONS,'root@'+ADDRESSES[role]+':'+remote,str(local)],check=True,timeout=40)  # nosec B603 # Guest sources are fixed paths or validated queue-ID paths; no shell.


def ready(output, include_relay=False):
    """Require the owned guest/host gate before any experiment or report submission."""
    args=['-IncludeRelay'] if include_relay else []
    subprocess.run([str(POWERSHELL),'-NoProfile','-File',str(ROOT/'tools/Test-LabReady.ps1'),
        '-OutputDirectory',str(output),*args],check=True,timeout=60)  # nosec B603 # Absolute executable and reviewed fixed script; output path is one argv value.


def dns_queries(case):
    """Query the selector actually used, preserving independent DNS observations."""
    selector=case.get('selector','lab1')
    return f'dig @10.77.0.20 {case["envelope"]} TXT; dig @10.77.0.20 _dmarc.{case["from"]} TXT; dig @10.77.0.20 {selector}._domainkey.{case["envelope"]} TXT'


def identities_match(case,record):
    """Check actual SMTP identities separately from headers, authentication and policy."""
    def addresses(name): return [item.get('addr') for item in record.get(name,[]) if isinstance(item,dict)]
    return (record.get('ip')==case['ip']
        and record.get('helo')==('relay.sender.test' if case.get('forward') else 'sender.sender.test')
        and addresses('envelope_from')==['analyst@'+case['envelope']]
        and addresses('envelope_to')==['analyst@recipient.test']
        and addresses('header_from')==['analyst@'+case['from']])


def signature_identity_matches(raw,domain,selector):
    """Check the intended signing identity before verification; this does not validate cryptography."""
    headers=BytesParser(policy=policy.default).parsebytes(raw).get_all('DKIM-Signature',[])
    if len(headers)!=1: return False
    tags={}
    for item in str(headers[0]).split(';'):
        if '=' not in item: continue
        name,value=item.split('=',1); name=name.strip()
        if name in tags: return False
        tags[name]=value.strip()
    return tags.get('d')==domain and tags.get('s')==selector


def current_queue_logs(raw,qid,collected):
    """Exclude reused queue IDs and substring matches from disposition proof; retain candidates too."""
    if not re.fullmatch(r'[A-Za-z0-9]{5,30}',qid): raise ValueError('Unsafe queue ID')
    lines=[]
    postfix=re.compile(r'\]: '+re.escape(qid)+r': ')
    rspamd=re.compile(r'(?:queue-id|qid): <'+re.escape(qid)+r'>')
    for line in raw.decode('utf-8',errors='replace').splitlines():
        if not (postfix.search(line) or rspamd.search(line)): continue
        try:
            stamp=line.split(' ',1)[0] if line[10:11]=='T' else line[:19].replace(' ','T')
            date=datetime.fromisoformat(stamp)
            if date.tzinfo is None: date=date.replace(tzinfo=timezone.utc) # Guest logs are explicitly UTC.
            moment=date.timestamp()
        except ValueError: continue
        if collected-1 <= moment <= collected+600: lines.append(line)
    return ('\n'.join(lines)+'\n').encode()


def validate_case(case):
    if not re.fullmatch(r'S[0-9]{2}[a-z]?',case['id']): raise ValueError('Invalid scenario ID')
    if case['from'] not in ('sender.test','lookalike.test','mail.sender.test'): raise ValueError('Unapproved visible domain')
    if case['envelope'] not in ('sender.test','lookalike.test'): raise ValueError('Unapproved envelope domain')
    if case['ip'] not in ('10.77.0.10','10.77.0.11','10.77.0.30'): raise ValueError('Unapproved source IP')
    if case['policy'] not in ('none','quarantine','reject'): raise ValueError('Unknown DMARC policy')
    if case.get('alignment','r') not in ('r','s'): raise ValueError('Unknown alignment')
    if not isinstance(case['signed'],bool): raise ValueError('Signing flag must be Boolean')
    if case.get('selector','lab1') not in ('lab1','lab2'): raise ValueError('Unapproved selector')
    for key,allowed in [('dns',('missing-spf','duplicate-dmarc','lookup-limit','unavailable')),('key',('missing','wrong')),('mutate',('body','subject'))]:
        if key in case and case[key] not in allowed: raise ValueError('Unknown '+key+' mode')
    for key in ('forward','forged','deceptive','warm','keep_cache'):
        if key in case and not isinstance(case[key],bool): raise ValueError('Mode must be Boolean: '+key)
    if case.get('forward') and case['id'] not in ('S09f','S09m'): raise ValueError('Unsupported relay scenario')
    if '\r' in case['name'] or '\n' in case['name'] or len(case['name'])>120: raise ValueError('Unsafe scenario name')


def replace_zone(base, case):
    alignment=case.get('alignment','r')
    # Windows text newline translation must not create blank lines ahead of $TTL on replay.
    lines=[line.strip() for line in base.splitlines() if line.strip()]
    lines=[line for line in lines if not any(line.startswith(name+' IN TXT') for name in ('_dmarc.sender','_dmarc.lookalike','_dmarc.mail.sender'))]
    # Insert policy under initial test origin, not the final DKIM domain origin.
    policies=[f'_dmarc.{domain} IN TXT "v=DMARC1; p={case["policy"]}; rua=mailto:reports@recipient.test; adkim={alignment}; aspf={alignment}"' for domain in ('sender','lookalike')]
    if case['from']=='mail.sender.test':
        # .test is private lab DNS: publish the child policy explicitly rather than assume PSL fallback.
        policies.append(f'_dmarc.mail.sender IN TXT "v=DMARC1; p={case["policy"]}; adkim={alignment}; aspf={alignment}"')
    insert_at=next(i+1 for i,line in enumerate(lines) if line.startswith('$TTL '))
    lines[insert_at:insert_at]=policies
    if case.get('dns')=='duplicate-dmarc': lines.insert(insert_at,'_dmarc.sender IN TXT "v=DMARC1; p=reject"')
    if case.get('dns') in ('missing-spf','lookup-limit'):
        lines=[line for line in lines if not line.startswith('sender IN TXT')]
    if case.get('dns')=='lookup-limit':
        # DNS TXT character strings are at most 255 octets; SPF concatenates adjacent strings.
        includes=[f'include:i{i}.sender.test' for i in range(11)]
        records=['sender IN TXT "v=spf1 '+ ' '.join(includes[:6])+' " "'+' '.join(includes[6:])+' -all"']
        records += [f'i{i}.sender IN TXT "v=spf1 -all"' for i in range(11)]
        lines[insert_at:insert_at]=records
    if case.get('key'):
        # DNS text records are multi-line; remove only the selected sender selector block.
        zone='\n'.join(lines)+'\n'
        head,sender_part=zone.split('$ORIGIN sender.test.\n',1)
        sender_part=re.sub(r'lab1\._domainkey IN TXT \(.*?\)\s*;?', '',sender_part,count=1,flags=re.S)
        zone=head+'$ORIGIN sender.test.\n'+sender_part
        if case['key']=='wrong':
            public='\n'.join(lines).split('$ORIGIN lookalike.test.\n',1)[1]
            zone=zone.replace('$ORIGIN sender.test.\n','$ORIGIN sender.test.\n'+public+'\n')
        return zone
    return '\n'.join(lines)+'\n'


def message(case, run_id=None):
    display='Campus Security Team' if case.get('deceptive') else 'Synthetic Lab Analyst'
    text=f'From: {display} <analyst@{case["from"]}>\r\nTo: Analyst <analyst@recipient.test>\r\nSubject: Synthetic {case["id"]} {case["name"]}\r\nMessage-ID: <{case["id"]}@sender.test>\r\nX-Lab-Scenario: {case["id"]}\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n'
    if run_id: text += f'X-Lab-Run: {run_id}\r\n'
    if case.get('forged'):
        text += 'Authentication-Results: receiver.recipient.test; spf=pass; dkim=pass; dmarc=pass\r\nAuthentication-Results: conflicting.test; spf=fail; dkim=fail; dmarc=fail\r\nReceived: from trusted.test (trusted.test [10.77.0.10]) by receiver.recipient.test with ESMTP id FORGED\r\n'
    text += '\r\nHarmless synthetic lab content. No real credentials or attachments.\r\n'
    if case.get('deceptive'): text += 'Urgent: review your fictional account at hxxps://portal[.]lookalike[.]test. Do not enter credentials.\r\n'
    return text.encode()


def run_case(case, output):
    validate_case(case)
    output.mkdir(parents=True,exist_ok=False)
    (output/'expected.json').write_text(json.dumps(case,indent=2))
    ready(output/'gate',case.get('forward',False))
    original=output/'original.eml'
    run_id=uuid.uuid4().hex
    started=time.time()
    (output/'run.json').write_text(json.dumps({'run_id':run_id,'started_unix':started},indent=2))
    original.write_bytes(message(case,run_id))
    base=ssh('receiver','cat /etc/bind/peal.test.zone').stdout.decode()
    zone=output/'dns.zone'
    zone.write_text(replace_zone(base,case),newline='\n')
    upload('receiver',zone,'/opt/peal/case.zone')
    submitted=output/'submitted-to-receiver.eml'
    selector_before=None
    try:
        restart='named' if case.get('warm') else 'named rspamd'
        ssh('receiver','named-checkzone test /opt/peal/case.zone && cp /opt/peal/case.zone /etc/bind/peal.test.zone && systemctl restart '+restart)
        if case['signed']:
            saved_selector=ssh('sender',"grep '^selector = ' /etc/rspamd/local.d/dkim_signing.conf").stdout.decode().strip()
            match=re.fullmatch(r'selector = "(lab1|lab2)";',saved_selector)
            if not match: raise ValueError('Unrecognized initial signing selector')
            selector_before=match[1]
            upload('sender',original,'/opt/peal/case-original.eml')
            selector=case.get('selector','lab1')
            ssh('sender',"sed -i 's/^selector = .*/selector = \""+selector+"\";/' /etc/rspamd/local.d/dkim_signing.conf && systemctl restart rspamd && postconf -e 'defer_transports = smtp' && postfix reload")
            time.sleep(1)
            sender=ssh('sender',f'swaks --server 127.0.0.1 --helo sender.sender.test --from analyst@{case["envelope"]} --to analyst@recipient.test --data @/opt/peal/case-original.eml --timeout 15')
            (output/'sender-smtp.txt').write_bytes(sender.stdout+sender.stderr)
            queue=re.search(rb'queued as ([A-Za-z0-9]+)',sender.stdout)
            if not queue: raise ValueError('Missing sender queue ID')
            qid=queue[1].decode()
            raw=ssh('sender','postcat -bhq '+qid).stdout
            (output/'sender-postfix-queue.eml').write_bytes(raw)
            # Remove Postfix postcat display marker if present; retain display bytes separately.
            raw=re.sub(rb'^\*\*\* MESSAGE CONTENTS[^\n]*\n',b'',raw)
            raw=re.sub(rb'\n\*\*\* HEADER EXTRACTED[^\n]*\n.*',b'\n',raw,flags=re.S)
            raw=re.sub(rb'\n\*\*\* MESSAGE FILE END[^\n]*\n?',b'\n',raw)
            if not signature_identity_matches(raw,case['envelope'],selector): raise ValueError('Sender signature identity/selector differs from the requested case')
            submitted.write_bytes(raw)
            # Delete only this preserved disposable staging queue entry.
            ssh('sender','postsuper -d '+qid)
        else: submitted.write_bytes(original.read_bytes())
        raw=submitted.read_bytes()
        if case.get('mutate')=='body': raw += b'\nSynthetic mailing-list footer added after signing.\n'
        if case.get('mutate')=='subject': raw=re.sub(rb'(?m)^Subject:[^\r\n]*',b'Subject: changed after signing',raw)
        submitted.write_bytes(raw)
        upload('sender',submitted,'/opt/peal/case-submitted.eml')
        answers=ssh('sender',dns_queries(case))
        (output/'dns-answers.txt').write_bytes(answers.stdout+answers.stderr)
        if case.get('dns')=='unavailable': ssh('receiver','systemctl stop named')
        target='10.77.0.30' if case.get('forward') else '10.77.0.20'
        source='10.77.0.10' if case.get('forward') else case['ip']
        transcript=ssh('sender',f'swaks --server {target} --local-interface {source} --helo sender.sender.test --from analyst@{case["envelope"]} --to analyst@recipient.test --data @/opt/peal/case-submitted.eml --timeout 15',check=False)
        (output/'receiver-smtp.txt').write_bytes(transcript.stdout+transcript.stderr)
        time.sleep(3 if case.get('forward') else 1)
        if case.get('forward'):
            for filename in ('before.eml','after.eml','forward.json'):
                download('relay','/var/lib/peal-relay/'+run_id+'/'+filename,output/('relay-'+filename))
            (output/'relay-logs.txt').write_bytes(ssh('relay',f'grep -F {run_id} /var/log/mail.log; tail -60 /var/log/mail.log').stdout)
        finder="python3 -c " + shlex.quote("import json,pathlib; rows=[(p,json.loads(p.read_text())) for p in pathlib.Path('/var/lib/rspamd/peal').glob('*.json')]; matches=[str(p) for p,d in rows if d.get('scenario_claim')=="+repr(case['id'])+" and d.get('run_claim')=="+repr(run_id)+" and d.get('collected_unix',0)>="+str(int(started)-2)+"]; assert len(matches)==1, 'Missing or ambiguous fresh receiver record'; print(matches[0])")
        record_path=ssh('receiver',finder).stdout.decode().strip()
        if not re.fullmatch(r'/var/lib/rspamd/peal/[A-Za-z0-9]+\.json',record_path): raise ValueError('Unsafe record path')
        download('receiver',record_path,output/'receiver.json')
        receiver_record=json.loads(bounded_bytes(output/'receiver.json'))
        record=summarize_receiver(output/'receiver.json')
        qid=record['queue_id']
        logs=ssh('receiver',f'grep {qid} /var/log/mail.log; grep {qid} /var/log/rspamd/rspamd.log; postqueue -j')
        (output/'receiver-log-candidates.txt').write_bytes(logs.stdout+logs.stderr)
        current=current_queue_logs(logs.stdout,qid,receiver_record['collected_unix'])
        (output/'receiver-logs.txt').write_bytes(current)
        if case['disposition']=='rejected':
            disposition='rejected' if re.search(rb'<[^\r\n]*\b5[0-9]{2}\b',transcript.stdout) and b'milter-reject' in current else 'unproven'
        elif case['disposition']=='held':
            queues=ssh('receiver','postqueue -j').stdout.splitlines()
            held=any(json.loads(line).get('queue_id')==qid and json.loads(line).get('queue_name')=='hold' for line in queues)
            disposition='held' if held else 'unproven'
            if held: (output/'post-receiver-held.eml').write_bytes(ssh('receiver','postcat -bhq '+qid).stdout)
        else:
            found=re.search(rb'status=sent \(250 2\.0\.0 Ok: queued as ([A-Za-z0-9]+)\)',current)
            if found:
                capture=found[1].decode()
                ssh('receiver',f'curl --fail -s http://127.0.0.1:8025/api/v1/message/{capture}/raw -o /opt/peal/case-post.eml')
                download('receiver','/opt/peal/case-post.eml',output/'post-receiver.eml')
                disposition='delivered'
            else: disposition='unproven'
        record['disposition']=disposition
        record['identities_match']=identities_match(case,receiver_record)
        record['expected_match']=all(record.get(field)==case[field] for field in ('spf','dkim','dmarc','disposition')) and record['identities_match']
        record['swaks_exit']=transcript.returncode
        (output/'observed.json').write_text(json.dumps(record,indent=2))
        versions=ssh('receiver','dpkg-query -W; date -u; rspamadm configdump; postconf -n')
        (output/'versions-config-time.txt').write_bytes(versions.stdout+versions.stderr)
    finally:
        restore=output/'restore.zone'
        restore.write_text('\n'.join(line for line in base.splitlines() if line.strip())+'\n',newline='\n')
        upload('receiver',restore,'/opt/peal/restore.zone')
        restart='named' if case.get('keep_cache') else 'named rspamd'
        ssh('receiver','cp /opt/peal/restore.zone /etc/bind/peal.test.zone && systemctl restart '+restart)
        if selector_before:
            ssh('sender',"sed -i 's/^selector = .*/selector = \""+selector_before+"\";/' /etc/rspamd/local.d/dkim_signing.conf && systemctl restart rspamd")
        restore.unlink()
    # Seal only after restoration completed. An interrupted cleanup remains an unsealed attempt.
    (output/'restoration.json').write_text(json.dumps({'dns_restored':True,'selector_restored':selector_before,
        'receiver_cache_kept':case.get('keep_cache',False),'completed_unix':time.time()},indent=2))
    (output/'SHA256.json').write_text(json.dumps(manifest(output),indent=2))
    return record


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('scenario_id')
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    matrix=json.loads((ROOT/'scenarios/matrix.json').read_text())
    selected=[case for case in matrix if case['id']==args.scenario_id]
    if len(selected)!=1: raise ValueError('Unknown scenario')
    observed=run_case(selected[0],args.output.resolve())
    print(json.dumps({key:observed[key] for key in ('spf','dkim','dmarc','disposition','expected_match')},indent=2))
    raise SystemExit(0 if observed['expected_match'] else 2)
