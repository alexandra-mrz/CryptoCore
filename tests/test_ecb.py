import unittest

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

from cryptocore.modes.ecb import ecb_encrypt, ecb_decrypt


class TestECB(unittest.TestCase):
    def setUp(self):
        self.key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")

    def test_round_trip(self):
        samples = [
            b"",
            b"Hello!",
            b"A" * 16,
            b"B" * 17,
            "Привет, мир!".encode("utf-8"),
            bytes(range(256)),
        ]

        for data in samples:
            with self.subTest(length=len(data)):
                encrypted = ecb_encrypt(data, self.key)
                decrypted = ecb_decrypt(encrypted, self.key)
                self.assertEqual(decrypted, data)

    def test_reference_encryption(self):
        data = bytes(range(50))

        cipher = AES.new(self.key, AES.MODE_ECB)
        expected = cipher.encrypt(pad(data, AES.block_size))

        self.assertEqual(ecb_encrypt(data, self.key), expected)

    def test_full_padding_block(self):
        encrypted = ecb_encrypt(b"A" * 16, self.key)
        self.assertEqual(len(encrypted), 32)

    def test_invalid_ciphertext_length(self):
        for data in [b"", b"123"]:
            with self.subTest(data=data):
                with self.assertRaises(ValueError):
                    ecb_decrypt(data, self.key)

    def test_invalid_padding(self):
        cipher = AES.new(self.key, AES.MODE_ECB)

        # Последний байт требует два байта 02, но перед ним стоит 01.
        invalid_data = b"A" * 14 + b"\x01\x02"
        encrypted = cipher.encrypt(invalid_data)

        with self.assertRaises(ValueError):
            ecb_decrypt(encrypted, self.key)

    def test_invalid_key_length(self):
        with self.assertRaises(ValueError):
            ecb_encrypt(b"Hello", b"short")

        with self.assertRaises(ValueError):
            ecb_decrypt(b"A" * 16, b"short")


if __name__ == "__main__":
    unittest.main()