import unittest

from Crypto.Cipher import AES

from cryptocore.modes.cfb import cfb_encrypt, cfb_decrypt


class TestCFB(unittest.TestCase):
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
                encrypted = cfb_encrypt(data, self.key, self.iv)
                decrypted = cfb_decrypt(encrypted, self.key, self.iv)
                self.assertEqual(decrypted, data)

    def test_reference_encryption(self):
        data = bytes(range(50))

        cipher = AES.new(
            self.key,
            AES.MODE_CFB,
            iv=self.iv,
            segment_size=128,
        )
        expected = cipher.encrypt(data)

        self.assertEqual(cfb_encrypt(data, self.key, self.iv), expected)

    def test_no_padding(self):
        for size in [0, 1, 15, 16, 17, 50]:
            with self.subTest(size=size):
                data = b"A" * size
                encrypted = cfb_encrypt(data, self.key, self.iv)
                self.assertEqual(len(encrypted), len(data))

    def test_invalid_key_length(self):
        with self.assertRaises(ValueError):
            cfb_encrypt(b"Hello", b"short", self.iv)

        with self.assertRaises(ValueError):
            cfb_decrypt(b"Hello", b"short", self.iv)

    def test_invalid_iv_length(self):
        with self.assertRaises(ValueError):
            cfb_encrypt(b"Hello", self.key, b"short")

        with self.assertRaises(ValueError):
            cfb_decrypt(b"Hello", self.key, b"short")


if __name__ == "__main__":
    unittest.main()