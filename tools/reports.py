"""Collect locally delivered Rspamd aggregate reports; preserve Redis backup before consumption.

Only disposable owned receiver, fixed local report recipients, pinned SSH and loopback API.
The report generator consumes its own report keys. No FLUSHDB or remote report destinations.
"""
import argparse
import gzip
import io
import json
import re
import time
import xml.etree.ElementTree as ET  # nosec B405 # Strict UTF-8, bounded decompression, DTD/entity prohibition below; covered by hostile XML tests.
from email import policy
from email.parser import BytesParser
from pathlib import Path
from tools.lab import ssh,download,upload,ready
from tools.evidence import manifest,MAX_BYTES


def extract_report(raw):
    if len(raw)>MAX_BYTES: raise ValueError('Report MIME exceeds limit')
    message=BytesParser(policy=policy.default).parsebytes(raw)
    payloads=[part.get_payload(decode=True) for part in message.walk() if part.get_content_type()=='application/gzip']
    if len(payloads)!=1: raise ValueError('Expected one gzip report')
    with gzip.GzipFile(fileobj=io.BytesIO(payloads[0])) as stream:
        xml=stream.read(MAX_BYTES+1)
    if len(xml)>MAX_BYTES: raise ValueError('Oversized XML')
    text=xml.decode('utf-8',errors='strict')
    if '\x00' in text or re.search(r'<!\s*(DOCTYPE|ENTITY)',text,re.I):
        raise ValueError('Oversized or entity-bearing report XML')
    root=ET.fromstring(text)  # nosec B314 # UTF-16/NUL and all DTD/entities rejected before parsing, 2 MiB decoded bound; tests include encoding bypass.
    if root.tag!='feedback': raise ValueError('Not DMARC feedback XML')
    rows=[]
    for node in root.findall('record'):
        rows.append({'source_ip':node.findtext('row/source_ip'),'count':int(node.findtext('row/count')),
            'disposition':node.findtext('row/policy_evaluated/disposition'),
            'aligned_spf':node.findtext('row/policy_evaluated/spf'),'aligned_dkim':node.findtext('row/policy_evaluated/dkim'),
            'header_from':node.findtext('identifiers/header_from')})
    return xml,{'domain':root.findtext('policy_published/domain'),
        'begin':int(root.findtext('report_metadata/date_range/begin')),
        'end':int(root.findtext('report_metadata/date_range/end')),'rows':rows}


def collect(output,begin=None):
    output.mkdir(parents=True,exist_ok=False)
    ready(output/'gate-before')
    if ssh('receiver','cat /etc/peal-owned').stdout.strip()!=b'PEAL-receiver': raise ValueError('Wrong guest')
    config=ssh('receiver','rspamadm configdump dmarc').stdout
    if b'smtp = "127.0.0.1"' not in config or b'reports@recipient.test' not in config:
        raise ValueError('Reporting destination changed')
    (output/'reporting-config.txt').write_bytes(config)
    date=ssh('receiver','date -u +%Y%m%d').stdout.decode().strip()
    if not re.fullmatch('[0-9]{8}',date): raise ValueError('Invalid UTC date')
    ssh('receiver','redis-cli --rdb /opt/peal/report-before.rdb')
    download('receiver','/opt/peal/report-before.rdb',output/'redis-before.rdb')
    before=json.loads(ssh('receiver','curl --fail -s http://127.0.0.1:8025/api/v1/messages?limit=500').stdout)
    ids={m['ID'] for m in before['messages']}
    if begin is not None:
        now=int(ssh('receiver','date -u +%s').stdout)
        if not now-86400 <= begin <= now: raise ValueError('Window begin must be within the preceding day')
        # Upstream CLI dates select Redis keys but metadata always ends at today's midnight.
        # A separately preserved two-edit lab adapter supports a current-day bounded experiment.
        source=ssh('receiver','cat /usr/share/rspamd/lualib/rspamadm/dmarc_report.lua').stdout
        old=b'local start_collection = today_midnight()'
        if source.count(old)!=1: raise ValueError('Unsupported upstream report source')
        (output/'upstream-report.lua').write_bytes(source)
        adapted=source.replace(old,b'local start_collection = os.time() -- PEAL current-window adapter').replace(b"name = 'dmarc_report',",b"name = 'peal_report',")
        (output/'current-window-report.lua').write_bytes(adapted)
        upload('receiver',output/'current-window-report.lua','/opt/peal/current-window-report.lua')
        (output/'prior-last-collection.txt').write_bytes(ssh('receiver','redis-cli GET rspamd_dmarc_last_collection').stdout)
        ssh('receiver','redis-cli SET rspamd_dmarc_last_collection '+str(begin))
        ssh('receiver','install -m 0644 /opt/peal/current-window-report.lua /usr/share/rspamd/lualib/rspamadm/peal_report.lua')
        command='rspamadm peal_report -v '+date
    else: command='rspamadm dmarc_report -v '+date
    result=ssh('receiver',command,check=False)
    (output/'generator.txt').write_bytes(result.stdout+result.stderr)
    if result.returncode: raise ValueError('Report generation failed; inspect preserved log')
    time.sleep(2)
    after=json.loads(ssh('receiver','curl --fail -s http://127.0.0.1:8025/api/v1/messages?limit=500').stdout)
    reports=[]
    for item in after['messages']:
        if item['ID'] in ids or not item['Subject'].startswith('Report Domain:'): continue
        capture=item['ID']
        if not re.fullmatch('[A-Za-z0-9]+',capture): raise ValueError('Unsafe capture ID')
        raw=ssh('receiver','curl --fail -s http://127.0.0.1:8025/api/v1/message/'+capture+'/raw').stdout
        xml,summary=extract_report(raw)
        (output/(capture+'.eml')).write_bytes(raw)
        (output/(capture+'.xml')).write_bytes(xml)
        summary['capture_id']=capture
        reports.append(summary)
    if not reports: raise ValueError('No actual aggregate report arrived')
    (output/'reports.json').write_text(json.dumps(reports,indent=2))
    (output/'SHA256.json').write_text(json.dumps(manifest(output),indent=2))
    return reports


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--begin',type=int,help='Use documented two-edit lab adapter for a current-day UTC window')
    args=parser.parse_args()
    print(json.dumps(collect(args.output.resolve(),args.begin),indent=2))
