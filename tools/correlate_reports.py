"""Assert an exclusive controlled report window matches queue-correlated scenario traffic.

Supports exact-alignment controlled windows only; report outcomes are pass/fail aggregates,
not substitutes for detailed mechanism errors or independent delivery evidence.
"""
import argparse
import json
from collections import Counter
from pathlib import Path
from tools.evidence import verify


def correlate(window,reports):
    verify(reports)
    data=json.loads((reports/'reports.json').read_text())
    actual=Counter(); expected=Counter()
    for report in data:
        if type(report['begin']) is not int or type(report['end']) is not int or report['begin']>=report['end']:
            raise ValueError('Malformed/reversed report window')
        for row in report['rows']:
            if type(row['count']) is not int or row['count']<=0: raise ValueError('Non-positive/non-integer aggregate count')
            if row['header_from']!=report['domain']: raise ValueError('Report header identity differs from controlled policy domain')
            actual[(report['domain'],row['source_ip'],row['aligned_spf'],row['aligned_dkim'],row['disposition'])]+=row['count']
    for bundle in window.iterdir():
        if not bundle.is_dir() or not (bundle/'observed.json').exists(): continue
        verify(bundle)
        case=json.loads((bundle/'expected.json').read_text())
        seen=json.loads((bundle/'observed.json').read_text())
        raw=json.loads((bundle/'receiver.json').read_text())
        if not seen['expected_match'] or case['from']!=case['envelope']:
            raise ValueError('Window must use passing assertions with exact-alignment identities')
        bounds=[r for r in data if r['domain']==case['from']]
        if len(bounds)!=1 or not bounds[0]['begin']<=raw['collected_unix']<=bounds[0]['end']:
            raise ValueError('Traffic outside report date range')
        disposition={'delivered':'none','held':'quarantine','rejected':'reject'}[seen['disposition']]
        expected[(case['from'],seen['ip'],'pass' if seen['spf']=='pass' else 'fail',
            'pass' if seen['dkim']=='pass' else 'fail',disposition)]+=1
    if not expected or expected!=actual: raise ValueError('Report counts/identities/results differ from controlled traffic')
    return {'status':'passed','messages':sum(expected.values()),'reports':len(data),
        'window':str(window),'report_bundle':str(reports),'limits':'Requires exclusive lab window. Report disposition remains separately checked against queue/SMTP evidence.'}


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--window',type=Path,required=True)
    parser.add_argument('--reports',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    result=correlate(args.window,args.reports)
    with args.output.open('x') as file: json.dump(result,file,indent=2)
