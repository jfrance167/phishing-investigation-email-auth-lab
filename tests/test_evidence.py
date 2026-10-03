import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from tools import evidence
from tools.evidence import claims, manifest, verify, summarize_receiver


class EvidenceTests(unittest.TestCase):
    def test_forged_own_authserv_and_conflicting_headers_remain_claims(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)/'forged.eml'
            path.write_bytes(b'Authentication-Results: receiver.recipient.test; spf=pass; dmarc=pass\r\nAuthentication-Results: other.test; spf=fail\r\n\r\n')
            results = claims(path)
            self.assertEqual(len(results),2)
            self.assertTrue(all(r['trust']=='unverified-submitted-claim' for r in results))

    def test_manifest_detects_tamper_addition_and_removal(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            (root/'raw.eml').write_bytes(b'original\x00bytes\r\n')
            (root/'SHA256.json').write_text(json.dumps(manifest(root)))
            verify(root)
            (root/'extra').write_bytes(b'added')
            with self.assertRaises(ValueError): verify(root)
            (root/'extra').unlink()
            (root/'raw.eml').write_bytes(b'changed')
            with self.assertRaises(ValueError): verify(root)
            (root/'raw.eml').unlink()
            with self.assertRaises(ValueError): verify(root)

    def test_streamed_manifest_preserves_sha256_digest(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            raw=b'prior-evidence\x00bytes\r\n'*5
            (root/'raw.eml').write_bytes(raw)
            self.assertEqual(manifest(root)['raw.eml'],hashlib.sha256(raw).hexdigest())

    def test_manifest_enforces_per_file_and_total_byte_limits(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            (root/'oversized.bin').write_bytes(b'x'*33)
            with patch.object(evidence,'HASH_CHUNK_BYTES',8), \
                 patch.object(evidence,'MAX_FILE_BYTES',32), \
                 patch.object(evidence,'MAX_BUNDLE_BYTES',64):
                with self.assertRaisesRegex(ValueError,'per-file'):
                    manifest(root)
            (root/'oversized.bin').unlink()
            (root/'first.bin').write_bytes(b'a'*17)
            (root/'second.bin').write_bytes(b'b'*17)
            with patch.object(evidence,'HASH_CHUNK_BYTES',8), \
                 patch.object(evidence,'MAX_FILE_BYTES',32), \
                 patch.object(evidence,'MAX_BUNDLE_BYTES',32):
                with self.assertRaisesRegex(ValueError,'total-size'):
                    manifest(root)

    def test_manifest_enforces_file_count_limit(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            (root/'one').write_bytes(b'1')
            (root/'two').write_bytes(b'2')
            with patch.object(evidence,'MAX_BUNDLE_FILES',1):
                with self.assertRaisesRegex(ValueError,'file-count'):
                    manifest(root)

    def test_manifest_enforces_lazy_directory_entry_limit(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            (root/'one').write_bytes(b'1')
            (root/'two').write_bytes(b'2')
            with patch.object(evidence,'MAX_BUNDLE_ENTRIES',1):
                with self.assertRaisesRegex(ValueError,'directory-entry'):
                    manifest(root)

    def test_verify_bounds_manifest_json_read(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            (root/'SHA256.json').write_bytes(b' '*33)
            with patch.object(evidence,'MAX_MANIFEST_BYTES',32):
                with self.assertRaisesRegex(ValueError,'read limit'):
                    verify(root)

    def test_oversized_untrusted_message_is_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'large.eml'
            path.write_bytes(b'x'*2_097_153)
            with self.assertRaises(ValueError): claims(path)

    def test_receiver_record_does_not_infer_disposition_from_policy(self):
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'record.json'
            record={'source':'receiver-rspamd-milter','queue_id':'A12345','ip':'10.77.0.11',
                    'helo':'sender.test','envelope_from':[],'envelope_to':[],'action':'quarantine',
                    'symbols':[{'name':'DMARC_POLICY_QUARANTINE'}]}
            path.write_text(json.dumps(record))
            result=summarize_receiver(path)
            self.assertEqual(result['dmarc'],'fail')
            self.assertNotIn('disposition',result)

    def test_malformed_receiver_input_is_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'bad.json'
            path.write_text('{')
            with self.assertRaises(ValueError): summarize_receiver(path)
            path.write_text(json.dumps({'source':'attacker','queue_id':'A12345'}))
            with self.assertRaises(ValueError): summarize_receiver(path)
            for data in ([],None,{'source':'receiver-rspamd-milter','queue_id':12345}):
                path.write_text(json.dumps(data))
                with self.assertRaises(ValueError): summarize_receiver(path)


if __name__=='__main__': unittest.main()
