"""Reuse an explicitly selected, fingerprinted toolkit parser offline; auth headers remain claims.

Import executes reviewed toolkit module code. Review the file and confirm its SHA-256 first.
No enrich(), analyze(), web lookup, attachments or browser rendering are invoked.
"""
import argparse
import hashlib
import importlib.util
import json
import sys
from pathlib import Path
from tools.evidence import bounded_bytes,claims,summarize_receiver,verify


def adapt(toolkit,expected_hash,bundle):
    verify(bundle)
    if toolkit.name!='phishing_triage.py': raise ValueError('Select the reviewed toolkit parser')
    digest=hashlib.sha256(toolkit.read_bytes()).hexdigest()
    if digest!=expected_hash: raise ValueError('Toolkit source changed; inspect it before import')
    raw=bundle/'original.eml'
    bounded_bytes(raw)
    spec=importlib.util.spec_from_file_location('reviewed_peal_toolkit',toolkit)
    module=importlib.util.module_from_spec(spec)
    sys.modules[spec.name]=module
    spec.loader.exec_module(module)
    parsed=module.parse_email(raw).to_dict()
    return {'toolkit_sha256':digest,'toolkit_header_parse':parsed['message'],
        'toolkit_authentication_claim_summary':parsed['authentication'],
        'submitted_authentication_claims':claims(raw),
        'receiver_observation':summarize_receiver(bundle/'receiver.json'),
        'trust_note':'Toolkit header summaries are unverified claims; receiver provenance requires pinned collection, run/queue correlation and logs. Import requires prior source review.'}


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--toolkit',type=Path,required=True)
    parser.add_argument('--sha256',required=True)
    parser.add_argument('--bundle',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    result=adapt(args.toolkit.resolve(),args.sha256,args.bundle.resolve())
    with args.output.open('x') as file: json.dump(result,file,indent=2)
