import unittest
from tools.relay_filter import transform


class RelayTests(unittest.TestCase):
    def test_forward_retains_bytes_and_footer_changes_body_only(self):
        for scenario in ('S09f','S09m'):
            raw=f'X-Lab-Scenario: {scenario}\r\nX-Lab-Run: '+('a'*32)+'\r\n\r\nSynthetic body\r\n'
            changed=transform(raw.encode())[2]
            self.assertTrue(changed.startswith(raw.encode()))
            self.assertEqual(changed==raw.encode(),scenario=='S09f')

    def test_hostile_claims_cannot_select_files_or_transformations(self):
        for scenario,run_id in [('other','a'*32),('S09m','../../file'),('S09f','a'*31)]:
            with self.assertRaises(ValueError):
                transform(f'X-Lab-Scenario: {scenario}\r\nX-Lab-Run: {run_id}\r\n\r\n'.encode())
        with self.assertRaises(ValueError): transform(b'x'*2_097_153)
