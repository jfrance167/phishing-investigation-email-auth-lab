import json
import unittest
from pathlib import Path
from tools.lab import validate_case, replace_zone

CASE=json.loads((Path(__file__).resolve().parents[1]/'scenarios/matrix.json').read_text())[0]


class ScenarioBoundaryTests(unittest.TestCase):
    def test_shell_and_network_boundary_fields_are_rejected(self):
        for field,value in [('envelope','sender.test; reboot'),('from','other.com'),('ip','8.8.8.8'),
                            ('policy','none"; injected'),('alignment','x'),('id','../../S01'),('name','x\r\nFrom: injected'),
                            ('selector','lab1; reboot'),('dns','unknown'),('forged','true'),('forward',True)]:
            with self.subTest(field=field):
                with self.assertRaises(ValueError): validate_case(dict(CASE,**{field:value}))

    def test_dns_policy_follows_ttl_even_after_windows_newline_translations(self):
        base='$ORIGIN test.\r\r\n\r\r\n$TTL 30\r\r\n@ IN SOA ns.test. host.test. (1 30 30 3600 30)\r\r\n_dmarc.sender IN TXT "v=DMARC1; p=none"\r\r\n'
        zone=replace_zone(base,CASE)
        self.assertLess(zone.index('$TTL 30'),zone.index('_dmarc.sender'))
        self.assertNotIn('\r',zone)
        self.assertEqual(zone.count('_dmarc.sender IN TXT'),1)

    def test_all_predefined_cases_obey_boundaries(self):
        cases=json.loads((Path(__file__).resolve().parents[1]/'scenarios/matrix.json').read_text())
        for case in cases: validate_case(case)
