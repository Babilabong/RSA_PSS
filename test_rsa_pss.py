import unittest
from rsa_pss import generate_keys, sign, verify

class TestRSAPSS(unittest.TestCase):
    def setUp(self):
        self.public_key, self.private_key = generate_keys()
        self.message = b"Test message for RSA-PSS"
        self.signature = sign(self.message, self.private_key)

    def test_valid_signature(self):
        self.assertTrue(verify(self.message, self.signature, self.public_key))

    def test_tampered_message(self):
        tampered_message = b"Tampered message"
        self.assertFalse(verify(tampered_message, self.signature, self.public_key))

    def test_invalid_key(self):
        # Generate a new unrelated key pair
        other_public, other_private = generate_keys()
        self.assertFalse(verify(self.message, self.signature, other_public))

    def test_multiple_signatures(self):
        messages = [b"Message 1", b"Message 2", b"Message 3"]
        for msg in messages:
            sig = sign(msg, self.private_key)
            self.assertTrue(verify(msg, sig, self.public_key))

    def test_signature_length(self):
        sig_length_bytes = (self.signature.bit_length() + 7) // 8
        self.assertTrue(sig_length_bytes >= 256)


if __name__ == '__main__':
    unittest.main()
