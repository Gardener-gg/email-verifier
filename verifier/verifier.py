# TODO: Accept multiple addresses for email verification
# TODO: Handle errors according to status code.
# TODO: Retry on some responses.

import binascii
import os
from collections import namedtuple
from email.utils import parseaddr
import pprint
import smtplib
import socks

from dns import resolver
from socks_smtp import SocksSMTP as SMTP

blocked_keywords = ["spamhaus",
			"proofpoint",
			"cloudmark",
			"banned",
			"blacklisted",
			"blocked",
			"block list",
			"denied"]

proxy = {
    'socks4': socks.SOCKS4,
    'socks5': socks.SOCKS5,
    'http': socks.HTTP # does not guareentee it will work with HTTP
}

class UnknownProxyError(Exception):
    def __init__(self, proxy_type):
        self.msg = f"The proxy type {proxy_type} is not known\n Try one of socks4, socks5 or http"

class EmailFormatError(Exception):
    
    def __init__(self, msg):
        self.msg = msg

class SMTPRecepientException(Exception): # don't cover

    def __init__(self, code, response):
        self.code = code
        self.response = response

def handle_550(response):
    if any([keyword.encode() in response for keyword in blocked_keywords]):
        return "Blocked by mail server"
    return "Mailbox unavailable"

def handle_551(response):
    return "Mailbox has moved"

def handle_421(response):
    return "Try again later"

def handle_450(response):
    return "Mailbox busy"

def handle_other(response):
    return "Other Error"

handle_error = {
    550: handle_550,
    551: handle_551,
    450: handle_450,
    421: handle_421,
}


# create a namedtuple to hold the email address
Address = namedtuple("Address", ["name", "addr", "username", "domain"])

class Verifier:

    def __init__(self,
                 source_addr,
                 proxy_type = None,
                 proxy_addr = None,
                 proxy_port = None,
                 proxy_username = None,
                 proxy_password = None):
        """
        Initializes the Verifier object with proxy settings.
        :param proxy_type: One of `SOCKS4`, `SOCKS5` or `HTTP`.
        :param proxy_addr: Address of the proxy.
        :param proxy_port: Port of the proxy.
        :param proxy_username: Username to authenticate with.
        :param proxy_password: Password for the user. (Only when username is provided)
        """
        if proxy_type:
            try:
                self.proxy_type = proxy[proxy_type.lower()]
            except KeyError as e:
                raise UnknownProxyError(proxy_type)
        else:
            self.proxy_type = None
        self.source_addr = source_addr
        self.proxy_addr = proxy_addr
        self.proxy_port = proxy_port
        self.proxy_username = proxy_username
        self.proxy_password = proxy_password
    
    def _parse_address(self, email) -> Address:
        """
        Parses the email address provided and splits it 
        into username and domain.

        Returns a named tuple Address
        """
        name, addr = parseaddr(email)
        if not addr:
            raise EmailFormatError(f"email does not contain address: {email}")
        try:
            domain = addr.split('@')[-1]
            username = addr.split('@')[:-1][0]
        except IndexError:
            raise EmailFormatError(f"address provided is invalid: {email}")
        return Address(name, addr, username, domain)
    
    def _random_email(self, domain):
        """
        This method generates a random email by using the os.urandom
        for the domain provided in the parameter.
        """
        return f'{binascii.hexlify(os.urandom(20)).decode()}@{domain}'
    
    def _can_deliver(self,
                     exchange : str,
                     address : str):
        """
        Checks the deliverablity of an email to the given mail_exchange.
        Creates a connection using the SMTP and tries to add the email to 
        a recipients.

        :param exchange: The exchange url for the domain of email
        :param address: The email address to check for deliverablity

        :returns: A 3-tuple of host_exists, deliverable and catch_all
        """
        host_exists = False
        with SMTP(exchange[1],
                proxy_type=self.proxy_type,
                proxy_addr=self.proxy_addr,
                proxy_port=self.proxy_port,
                proxy_username=self.proxy_username,
                proxy_password=self.proxy_password) as smtp:
            host_exists = True
            smtp.helo()
            smtp.mail(self.source_addr)
            test_resp = smtp.rcpt(address.addr)
            catch_all_resp = smtp.rcpt(self._random_email(address.domain))
            if test_resp[0] == 250:
                deliverable = True
                if catch_all_resp[0] == 250:
                    catch_all = True
                else:
                    catch_all = False
            elif test_resp[0] >= 400:
                raise SMTPRecepientException(*test_resp)
        return host_exists, deliverable, catch_all

    def verify(self, email):
        """
        method that performs the verification on the passed
        email address.
        """
        lookup = {
            'address': None,
            'valid_format': False,
            'deliverable': False,
            'full_inbox': False,
            'host_exists': False,
            'catch_all': False,
        }
        try:
            lookup['address'] = self._parse_address(email)
            lookup['valid_format'] = True
        except EmailFormatError:
            lookup['address'] = f"{email}"
            return lookup
        
        # look for mx record and create a list of mail exchanges
        try:
            mx_record = resolver.query(lookup['address'].domain, 'MX')
            mail_exchangers = [exchange.to_text().split() for exchange in mx_record]
            lookup['host_exists'] = True
        except (resolver.NoAnswer, resolver.NXDOMAIN, resolver.NoNameservers):
            lookup['host_exists'] = False
            return lookup

        for exchange in mail_exchangers:
            try:
                host_exists, deliverable, catch_all = self._can_deliver(exchange, lookup['address'])
                if deliverable:
                    lookup['host_exists'] = host_exists
                    lookup['deliverable'] = deliverable
                    lookup['catch_all'] = catch_all
                    break
            except SMTPRecepientException as err:
                if err.code in [552, 441]:
                    lookup['full_inbox'] = True
                else:
                    lookup['message'] = handle_error.get(err.code, handle_other)(err.response)
            except smtplib.SMTPServerDisconnected as err:
                lookup['message'] = "Internal Error"
            except smtplib.SMTPConnectError as err:
                lookup['message'] = "Internal Error. Maybe blacklisted"

        return lookup
    
if __name__ == "__main__":
    v = Verifier(source_addr='user@example.com')
    email = input('Enter email to verify: ')
    l = v.verify(email)
    pprint.pprint(l)       