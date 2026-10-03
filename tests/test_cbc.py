import unittest

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

from cryptocore.modes.cbc import cbc_encrypt, cbc_decrypt


class TestCBC(unittest.TestCase):
    def setUp(self):
        self.key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
        self.iv = bytes.fromhex("00112233445566778899aabbccddeeff")

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
                encrypted = cbc_encrypt(data, self.key, self.iv)
                decrypted = cbc_decrypt(encrypted, self.key, self.iv)
                self.assertEqual(decrypted, data)

    def test_reference_encryption(self):
        data = bytes(range(50))

        cipher = AES.new(self.key, AES.MODE_CBC, iv=self.iv)
        expected = cipher.encrypt(pad(data, AES.block_size))

        self.assertEqual(cbc_encrypt(data, self.key, self.iv), expected)

    def test_full_padding_block(self):
        encrypted = cbc_encrypt(b"A" * 16, self.key, self.iv)
        self.assertEqual(len(encrypted), 32)

    def test_invalid_key_length(self):
        with self.assertRaises(ValueError):
            cbc_encrypt(b"Hello", b"short", self.iv)

        with self.assertRaises(ValueError):
            cbc_decrypt(b"A" * 16, b"short", self.iv)

    def test_invalid_iv_length(self):
        with self.assertRaises(ValueError):
            cbc_encrypt(b"Hello", self.key, b"short")

        with self.assertRaises(ValueError):
            cbc_decrypt(b"A" * 16, self.key, b"short")

    def test_invalid_ciphertext_length(self):
        for data in [b"", b"123"]:
            with self.subTest(data=data):
                with self.assertRaises(ValueError):
                    cbc_decrypt(data, self.key, self.iv)

    def test_invalid_padding(self):
        invalid_data = b"A" * 14 + b"\x01\x02"
        cipher = AES.new(self.key, AES.MODE_CBC, iv=self.iv)
        encrypted = cipher.encrypt(invalid_data)

        with self.assertRaises(ValueError):
            cbc_decrypt(encrypted, self.key, self.iv)


if __name__ == "__main__":
    unittest.main()