# -*- coding: utf-8 -*-
"""
Copyright(c) 2014, Cyan, Inc. All rights reserved.
"""

import os
import time
import unittest
from binascii import hexlify
from rsign import SignedRequest, get_auth_header_values


class TestRequest(unittest.TestCase):
    """ Verify request objects behave as expected """

    def setUp(self):
        ''' Validate the Authurization header has the correct format '''
        method = "POST"
        host = "example.com"
        path = "/path/to/resource"
        port = "8080"
        self.request = SignedRequest(method, host, path, port)
        # This doesn't have to be decoded on the other side.  It just has to be ascii printable
        self.nonce = hexlify(os.urandom(32))
        self.timestamp = str(int(time.time()))
        # This doesn't have to be decoded on the other side.  It just has to be ascii printable
        self.key_id = hexlify(os.urandom(32))
        self.key = hexlify(os.urandom(40))

    def test_request_valid(self):
        ''' Validate the request header validates correctly '''
        self.assertTrue(self.request.verify_signed_header(self._auth_header()[1], self.key),
                        "Verify a signed request header authenticates properly.")

    def test_rejects_tampered_key(self):
        self.assertFalse(self.request.verify_signed_header(self._auth_header()[1], self.key[:-1]),
                         "Verify a tampered with key or request doesn't verify properly")

    def test_rejects_tampered_method(self):
        headers = self._auth_header()
        self.request.method = "GET"  # different from the method we signed
        self.assertFalse(self.request.verify_signed_header(headers[1], self.key),
                         "Verify a tampered with key or request doesn't verify properly")

    def test_rejects_tampered_path(self):
        auth_header = self._auth_header()
        self.request.method, self.request.path = "POST", "/not/path"
        self.assertFalse(self.request.verify_signed_header(auth_header[1], self.key),
                         "Verify a tampered with key or request doesn't verify properly")

    def test_request_unicode(self):
        ''' Validate the request validates with unicode correctly '''
        self.key = u'¬˚∆œ∑¬˚œ∑´¬œ∑´∆˚∆ç∂√å∫∂√˚´∑ˆø'
        auth_header = self.request.get_signed_header(self.nonce, self.timestamp, self.key_id, self.key)
        self.assertTrue(self.request.verify_signed_header(auth_header[1], self.key))

    def test_get_auth_header_values(self):
        ''' Validate the Auth Header properly parses into dictionary '''
        header = 'MAC id="123", ts="123", nonce="nonce", mac="2tduYjW+ZTdQyN/aOQxk3fVBnaaNs5qMmnDVIfvp16g="'
        expect = dict(id="123", ts="123", nonce="nonce", mac="2tduYjW+ZTdQyN/aOQxk3fVBnaaNs5qMmnDVIfvp16g=")
        actual = get_auth_header_values(header)
        self.assertEqual(expect, actual, 'Assert header values are equivalent')

    def test_verify_signature_changes(self):
        self.request.method = 'POST'
        sig1 = self.request.sign_request(self.nonce, self.timestamp, self.key)

        self.request.method = 'GET'
        sig2 = self.request.sign_request(self.nonce, self.timestamp, self.key)

        self.assertNotEqual(sig1, sig2)

    def _auth_header(self):
        return self.request.get_signed_header(self.nonce, self.timestamp, self.key_id, self.key)


if __name__ == '__main__':
    unittest.main()
