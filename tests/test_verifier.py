from unittest import TestCase
from unittest.mock import patch

from .verifier import (Verifier,
                       EmailFormatError,
                       SMTPRecepientException,
                       Address)

class Record:
    def __init__(self, preference, server):
        self.server = server
        self.preference = preference

    def to_text(self):
        return f"{self.preference} {self.server}"

r1 = Record(10, f'smtp.example.com')
r2 = Record(21, f'smtp.example.l.com')
dns_response = [r1, r2]


class VerifierTestCase(TestCase):
    
    def setUp(self):
        self.verifier = Verifier(source_addr="user@example.com")
    
    def test_random_email(self):
        mail_one = self.verifier._random_email('gmail.com')
        mail_two = self.verifier._random_email('yandex.com')

        # test both emails are different
        self.assertNotEqual(mail_one.split('@')[0], mail_two.split('@')[0])
        # test email have @ character
        self.assertTrue('@' in mail_one and '@' in mail_two)
        self.assertTrue(mail_one.endswith('gmail.com'))
        self.assertTrue(mail_two.endswith('yandex.com'))
    
    def test_parse_address_raises_on_non_email(self):
        invalid_mail_address = 'not_an_email'
        with self.assertRaises(EmailFormatError) as err:
            self.verifier._parse_address(invalid_mail_address)
        
        invalid_mail = "NOT_MAIL <not_an_email>"
        with self.assertRaises(EmailFormatError) as err:
            self.verifier._parse_address(invalid_mail)
        
        self.assertEqual(err.exception.msg, "address provided is invalid: NOT_MAIL <not_an_email>")
        
        invalid_mail = "NO_MAIL <>"
        with self.assertRaises(EmailFormatError) as err:
            self.verifier._parse_address(invalid_mail)
        

        self.assertEqual(err.exception.msg, "email does not contain address: NO_MAIL <>")

    def test_parse_address_returns_address_on_valid_emails(self):
        valid_email = "user@domain.com"
        addr = self.verifier._parse_address(valid_email)
        self.assertTrue(isinstance(addr, Address))
        self.assertEqual(addr.username, "user")
        self.assertEqual(addr.domain, "domain.com")
        self.assertEqual(addr.addr, "user@domain.com")

        valid_email = "USER <user@domain.com>"
        addr = self.verifier._parse_address(valid_email)
        self.assertEqual(addr.name, "USER")
    
    @patch.object(Verifier, '_can_deliver', return_value=(True, True, False))
    @patch('dns.resolver.query', return_value=dns_response)
    def test_verifier(self, m_resolver, m_deliver):
        # some ugly patching and mocking to test the flow of verfier
        result = self.verifier.verify('user@example.com')
        addr = self.verifier._parse_address("user@example.com")
        m_resolver.assert_called_with('example.com', 'MX')
        m_deliver.assert_called_once_with(dns_response[0].to_text().split(), addr)
        