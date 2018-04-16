# Copyright(c) 2014, Cyan, Inc. All rights reserved.
import hmac
import hashlib
import binascii

from rsign._version import PY3


def _clean(string):
    """ Unicode to Byte conversion """
    try:
        return str(string)
    except UnicodeEncodeError:
        return string.encode('utf-8')


if not hasattr(hmac, 'compare_digest'):
    # Backport compare_digest to python 2.X
    # see http://bugs.python.org/review/15061/diff2/5181:5214/Lib/hmac.py
    # and http://bugs.python.org/issue15061
    def compare_digest(a, b):
        """Returns the equivalent of 'a == b', but avoids content based short
        circuiting to reduce the vulnerability to timing attacks."""
        # Consistent timing matters more here than data type flexibility
        if not (isinstance(a, bytes) and isinstance(b, bytes)):
            raise TypeError("inputs must be bytes instances")

        # We assume the length of the expected digest is public knowledge,
        # thus this early return isn't leaking anything an attacker wouldn't
        # already know
        if len(a) != len(b):
            return False

        # We assume that integers in the bytes range are all cached,
        # thus timing shouldn't vary much due to integer object creation
        result = 0
        for x, y in zip(a, b):
            result |= ord(x) ^ ord(y)
        return result == 0
    hmac.compare_digest = compare_digest


class Signature(object):
    """ Abstract class representing a cryptographic signature """

    def sign_string(self, key, text):
        """ Return the signing method's digest """
        raise NotImplementedError()

    def compare(self, s1, s2):
        """
        verify s1 == s2.  this _must_ be a function
        that provides constant time verification
        """
        raise NotImplementedError()

    def verify_signature(self, key, text, signature):
        """ Verify that the signature matches the received digest """
        actual = self.sign_string(key, text)
        return self.compare(signature, actual)


class HMACSignature(Signature):
    """ Sign and verify a string using HMAC """

    def __init__(self, hash_function=hashlib.sha256):
        self.hash_fn = hash_function

    def compare(self, s1, s2):
        return hmac.compare_digest(s1, s2)

    def sign_string(self, key, text):
        """ Return the signing method's digest """
        key, text = _clean(key), _clean(text)
        # Py3 hmac.new expects key as bytes. py2 expects str
        key3 = key.encode() if PY3 and isinstance(key, str) else key
        text3 = text.encode() if PY3 and isinstance(text, str) else text
        return hmac.new(key3, text3, self.hash_fn).digest()


class Base64Mixin(Signature):
    """ Encode a Signature using Base64 """

    def verify_signature(self, key, text, signature):
        """ Verify that the signature matches the received digest """
        binary = binascii.a2b_base64(signature)
        # Can't call our own sign_string because it's base64 too!
        actual = super(Base64Mixin, self).sign_string(key, text)
        return self.compare(binary, actual)

    def sign_string(self, key, text):
        """ Return the signing method's digest """
        binary = super(Base64Mixin, self).sign_string(key, text)
        # Py2 binascii.b2a_base64 gives us str, so str replacement
        # Py3 gives us bytes, so we can only replace with bytes
        newline = '\n'.encode() if PY3 else '\n'
        empty = ''.encode() if PY3 else ''
        signature = binascii.b2a_base64(binary).replace(newline, empty)

        return signature


class HMACBase64Signature(Base64Mixin, HMACSignature):
    """ HMAC Signed and Base64 encoded Signature """
    pass
