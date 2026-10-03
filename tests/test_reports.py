import gzip
import unittest
from email.message import EmailMessage
from tools.reports import extract_report


def wrap(xml):
    msg=EmailMessage()
    msg.set_content('Synthetic report')
    msg.add_attachment(gzip.compress(xml),maintype='application',subtype='gzip',filename='report.xml.gz')
    return msg.as_bytes()


class ReportBoundaryTests(unittest.TestCase):
    def test_expansion_and_entities_are_rejected(self):
        for xml in (b'x'*2_097_153,b'<!DOCTYPE feedback [<!ENTITY x "test">]><feedback/>',
                    '<!DOCTYPE feedback [<!ENTITY x "test">]><feedback/>'.encode('utf-16')):
            with self.assertRaises(ValueError): extract_report(wrap(xml))

    def test_unrelated_xml_and_missing_attachment_are_rejected(self):
        with self.assertRaises(ValueError): extract_report(wrap(b'<unrelated/>'))
        with self.assertRaises(ValueError): extract_report(b'Content-Type: text/plain\r\n\r\nno report')
