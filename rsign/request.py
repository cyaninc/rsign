# Copyright(c) 2014, Cyan, Inc. All rights reserved.
import re

from rsign.signature import HMACBase64Signature
from rsign._version import PY3


def get_auth_header_values(header_string):
    """ Returns a dict mapping the header keys to their values """
    # Get the header key and value (value matches any non-quote contained in quotes)
    reg = re.compile(r'(\w+)="([^"]+)"')
    return dict(reg.findall(header_string))


def normalize(timestamp, nonce, method, path, host, port):  # pylint: disable=R0913
    """ Accepts args as strings and returns the normalized form for signing """
    normalized = '\n'.join([
        timestamp,
        nonce.decode() if PY3 and isinstance(nonce, bytes) else nonce,
        method.upper(),
        path,
        host.lower(),
        port,
        ])
    return normalized


class SignedRequest(object):
    """ Signed request implementation """

    def __init__(self, method, host, path, port):
        self.method = method
        self.host = host
        self.path = path
        self.port = port

    def get_signed_header(self, nonce, timestamp, key_id, key):
        """ Returns the Authorization header as a tuple """
        signature = self.sign_request(nonce, timestamp, key)

        def conv(x):
            return x.decode() if PY3 and isinstance(x, bytes) else x

        header = 'MAC id="{}", ts="{}", nonce="{}", '\
            'mac="{}"'.format(conv(key_id), timestamp, conv(nonce), conv(signature))
        return ('Authorization', header)

    def verify_signed_header(self, header_string, key):
        """ Validates the request given the header string """
        h = get_auth_header_values(header_string)
        return self.verify_request(h['nonce'], h['ts'], key, h['mac'])

    def sign_request(self, nonce, timestamp, key):
        """ Returns the signature for the request's normalized string """
        normalized = normalize(
            timestamp,
            nonce,
            self.method.upper(),
            self.path,
            self.host.lower(),
            self.port,
            )
        signer = HMACBase64Signature()
        return signer.sign_string(key, normalized)

    def verify_request(self, nonce, timestamp, key, signature):
        """ Returns True if the signature matches the request, False otherwise """
        normalized = normalize(
            timestamp,
            nonce,
            self.method,
            self.path,
            self.host,
            self.port,
            )
        signer = HMACBase64Signature()
        return signer.verify_signature(key, normalized, signature)
