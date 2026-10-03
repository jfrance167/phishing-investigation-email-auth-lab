import io
import json
import tempfile
import unittest
from types import SimpleNamespace
from pathlib import Path
from unittest.mock import MagicMock,patch
from tools.evidence import bounded_bytes,manifest
from tools.lab import dns_queries,identities_match,current_queue_logs,signature_identity_matches,run_case
from tools.rotation import main as rotate,require_rotation_passes
from tools.reports import collect
from tools.queue_ledger import queue_ledger,authorized_queue
from tools.correlate_reports import correlate


def seal(root):
    (root/'SHA256.json').write_text(json.dumps(manifest(root)))


class ReviewRegressionTests(unittest.TestCase):
    def test_wrong_signing_selector_does_not_count_as_rotation(self):
        raw=b'DKIM-Signature: v=1; d=sender.test;\r\n s=lab2; b=fictional\r\n\r\nSynthetic'
        self.assertTrue(signature_identity_matches(raw,'sender.test','lab2'))
        self.assertFalse(signature_identity_matches(raw,'sender.test','lab1'))
        self.assertFalse(signature_identity_matches(raw,'lookalike.test','lab2'))
        self.assertFalse(signature_identity_matches(raw.replace(b'b=fictional',b's=lab1; b=fictional'),'sender.test','lab2'))

    def test_cleanup_failure_leaves_observed_case_unsealed(self):
        case={'id':'S07q','name':'Synthetic hold','from':'sender.test','envelope':'sender.test','ip':'10.77.0.11',
            'signed':False,'policy':'quarantine','spf':'fail','dkim':'none','dmarc':'fail','disposition':'held'}
        record={'source':'receiver-rspamd-milter','queue_id':'ABCDEF','collected_unix':1790997723,
            'run_claim':'a'*32,'scenario_claim':'S07q','ip':'10.77.0.11','helo':'sender.sender.test','action':'quarantine',
            'envelope_from':[{'addr':'analyst@sender.test'}],'envelope_to':[{'addr':'analyst@recipient.test'}],
            'header_from':[{'addr':'analyst@sender.test'}],
            'symbols':[{'name':name} for name in ('R_SPF_FAIL','R_DKIM_NA','DMARC_POLICY_QUARANTINE')]}
        def remote(role,command,check=True):
            if command.startswith('cp /opt/peal/restore.zone'): raise ValueError('Injected restoration failure')
            if command=='cat /etc/bind/peal.test.zone': data=b'$ORIGIN test.\n$TTL 30\n'
            elif command.startswith('python3 -c '): data=b'/var/lib/rspamd/peal/ABCDEF.json\n'
            elif command=='postqueue -j': data=b'{"queue_id":"ABCDEF","queue_name":"hold"}\n'
            else: data=b''
            return SimpleNamespace(stdout=data,stderr=b'',returncode=0)
        def receiver_copy(role,source,target): target.write_text(json.dumps(record))
        with tempfile.TemporaryDirectory() as folder,patch('tools.lab.ready'),patch('tools.lab.upload'),\
            patch('tools.lab.ssh',side_effect=remote),patch('tools.lab.download',side_effect=receiver_copy),\
            patch('tools.lab.uuid.uuid4',return_value=SimpleNamespace(hex='a'*32)),patch('tools.lab.time.sleep'):
            output=Path(folder)/'run'
            with self.assertRaises(ValueError): run_case(case,output)
            self.assertTrue((output/'observed.json').exists())
            self.assertFalse((output/'SHA256.json').exists())

    def test_changed_envelope_cannot_hide_behind_passing_authentication(self):
        case={'ip':'10.77.0.10','from':'sender.test','envelope':'sender.test'}
        raw={'ip':'10.77.0.10','helo':'sender.sender.test','envelope_from':[{'addr':'analyst@sender.test'}],
            'envelope_to':[{'addr':'analyst@recipient.test'}],'header_from':[{'addr':'analyst@sender.test'}]}
        self.assertTrue(identities_match(case,raw))
        for field,value in [('helo','forged.test'),('envelope_from',[{'addr':'analyst@lookalike.test'}]),
                            ('envelope_to',[]),('header_from',[{'addr':'analyst@lookalike.test'}])]:
            self.assertFalse(identities_match(case,dict(raw,**{field:value})))

    def test_disposition_proof_excludes_stale_or_substring_queue_logs(self):
        now=1790997723
        raw=(b'2026-10-03T03:22:03+00:00 receiver postfix/smtp[1]: A12345: status=sent\n'
            b'2026-10-03T03:22:03+00:00 receiver postfix/smtp[1]: BA12345: status=sent old-substring\n'
            b'2026-10-02T03:22:03+00:00 receiver postfix/smtp[1]: A12345: status=sent old-day\n')
        selected=current_queue_logs(raw,'A12345',now)
        self.assertIn(b'A12345: status=sent\n',selected)
        self.assertNotIn(b'old-substring',selected)
        self.assertNotIn(b'old-day',selected)

    def test_rotation_observes_actual_selector_and_fails_mismatches(self):
        case={'envelope':'sender.test','from':'sender.test','selector':'lab2'}
        self.assertIn('lab2._domainkey.sender.test',dns_queries(case))
        self.assertNotIn('lab1._domainkey',dns_queries(case))
        require_rotation_passes([{'expected_match':True}]*4)
        for rows in ([{'expected_match':True}]*3,[{'expected_match':True}]*3+[{'expected_match':False}]):
            with self.assertRaises(ValueError): require_rotation_passes(rows)

    def test_gate_failure_prevents_rotation_and_report_mutations(self):
        with tempfile.TemporaryDirectory() as folder:
            for module,operation,name in [('tools.rotation',rotate,'rotation'),('tools.reports',collect,'reports')]:
                with patch(module+'.ready',side_effect=ValueError('blocked')),patch(module+'.ssh') as remote:
                    with self.assertRaises(ValueError): operation(Path(folder)/name)
                    remote.assert_not_called()

    def test_growing_file_read_is_bounded(self):
        path=MagicMock()
        stream=MagicMock(wraps=io.BytesIO(b'x'*2_097_153))
        path.open.return_value.__enter__.return_value=stream
        with self.assertRaises(ValueError): bounded_bytes(path)
        stream.read.assert_called_once_with(2_097_153)
        path.read_bytes.assert_not_called()

    def test_queue_cleanup_needs_verified_role_queue_and_unique_nonce(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder); nonce='a'*32
            for name,record in [('expected.json',{'id':'S07q'}),('run.json',{'run_id':nonce}),
                                ('receiver.json',{'source':'receiver-rspamd-milter','queue_id':'A12345','scenario_claim':'S07q','run_claim':nonce})]:
                (root/name).write_text(json.dumps(record))
            seal(root); ledger=queue_ledger(root)
            raw=f'X-Lab-Scenario: S07q\r\nX-Lab-Run: {nonce}\r\n\r\nSynthetic'.encode()
            self.assertTrue(authorized_queue('receiver','A12345',raw,ledger))
            self.assertFalse(authorized_queue('receiver','OTHER1',raw,ledger))
            self.assertFalse(authorized_queue('relay','A12345',raw,ledger))
            self.assertFalse(authorized_queue('receiver','A12345',raw.replace(nonce.encode(),b'b'*32),ledger))
            self.assertFalse(authorized_queue('receiver','A12345',b'X-Lab-Scenario: S07q\r\n'+raw,ledger))
            (root/'receiver.json').write_text('{}')
            with self.assertRaises(ValueError): queue_ledger(root)

    def test_report_header_identity_and_time_range_cannot_be_ignored(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder); window=root/'window'; window.mkdir(); case=window/'S01'; case.mkdir()
            for name,record in [('expected.json',{'from':'sender.test','envelope':'sender.test'}),
                ('observed.json',{'expected_match':True,'ip':'10.77.0.10','spf':'pass','dkim':'pass','disposition':'delivered'}),
                ('receiver.json',{'collected_unix':150})]:
                (case/name).write_text(json.dumps(record))
            seal(case)
            reports=root/'reports'; reports.mkdir()
            base={'domain':'sender.test','begin':100,'end':200,'rows':[{'source_ip':'10.77.0.10','count':1,
                'aligned_spf':'pass','aligned_dkim':'pass','disposition':'none','header_from':'sender.test'}]}
            for bad in (None,'identity','time'):
                record=json.loads(json.dumps(base))
                if bad=='identity': record['rows'][0]['header_from']='lookalike.test'
                if bad=='time': record['begin']=250
                (reports/'reports.json').write_text(json.dumps([record])); seal(reports)
                if bad is None: self.assertEqual(correlate(window,reports)['messages'],1)
                else:
                    with self.assertRaises(ValueError): correlate(window,reports)
