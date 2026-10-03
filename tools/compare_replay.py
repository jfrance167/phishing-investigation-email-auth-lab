"""Compare actual post-reset outcomes with independently recorded earlier passing runs."""
import argparse
import json
from pathlib import Path
from tools.evidence import verify

FIELDS=('ip','spf','dkim','dmarc','disposition')


def compare(root,replay):
    verify(replay)
    rows=[]
    for after_file in sorted(replay.glob('S*/observed.json')):
        after=json.loads(after_file.read_text())
        after_time=json.loads((after_file.parent/'receiver.json').read_text())['collected_unix']
        earlier=[]
        for before_file in root.rglob('observed.json'):
            if before_file.is_relative_to(replay) or not (before_file.parent/'SHA256.json').exists(): continue
            before=json.loads(before_file.read_text())
            if before.get('scenario_claim')!=after['scenario_claim'] or not before.get('expected_match'): continue
            before_time=json.loads((before_file.parent/'receiver.json').read_text())['collected_unix']
            if before_time<after_time: earlier.append((before_time,before_file,before))
        if not earlier: raise ValueError('No independently recorded prior pass: '+after['scenario_claim'])
        _,path,before=max(earlier,key=lambda item:item[0])
        verify(path.parent)
        equal={field:before[field] for field in FIELDS}=={field:after[field] for field in FIELDS}
        rows.append({'scenario':after['scenario_claim'],'before':str(path.parent),'after':str(after_file.parent),
            'semantic_equal':equal,'normalized':{field:after[field] for field in FIELDS}})
    if len(rows)!=9 or not all(r['semantic_equal'] for r in rows): raise ValueError('Recorded replay differs')
    return {'status':'passed','compared_actual_runs':len(rows),'fields':FIELDS,'comparisons':rows,
        'note':'Queue IDs, timestamps and signatures are intentionally not required to match.'}


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--replay',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    root=Path(__file__).resolve().parents[1]/'evidence'
    result=compare(root,args.replay.resolve())
    with args.output.open('x') as file: json.dump(result,file,indent=2)
