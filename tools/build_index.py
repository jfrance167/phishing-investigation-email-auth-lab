"""Verify completed bundles and index latest semantic passes; retain failed/partial attempts."""
import json
from pathlib import Path
from tools.evidence import verify,manifest


def build(root):
    complete=[]; partial=[]; passing={}
    for path in root.rglob('observed.json'):
        row=json.loads(path.read_text())
        bundle=path.parent
        if not (bundle/'SHA256.json').exists(): partial.append(str(bundle.relative_to(root))); continue
        verify(bundle)
        item={'path':bundle.relative_to(root).as_posix(),'queue_id':row['queue_id'],
            'scenario':row['scenario_claim'],'ip':row['ip'],'spf':row['spf'],'dkim':row['dkim'],
            'dmarc':row['dmarc'],'disposition':row['disposition'],'expected_match':row['expected_match']}
        complete.append(item)
        if row['expected_match']:
            old=passing.get(row['scenario_claim'])
            if old is None or path.stat().st_mtime>old[0]: passing[row['scenario_claim']]=(path.stat().st_mtime,item)
    return {'completed_runs':complete,'latest_passing':{key:value[1] for key,value in sorted(passing.items())},
        'partial_observed_bundles':partial,'note':'Other early failures have no observed.json. They remain preserved and are not passes.'}


if __name__=='__main__':
    root=Path(__file__).resolve().parents[1]/'evidence'
    (root/'INDEX.json').write_text(json.dumps(build(root),indent=2))
