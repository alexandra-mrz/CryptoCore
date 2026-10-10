import unittest
from unittest.mock import patch

from cryptocore.csprng import generate_random_bytes


class TestCSPRNG(unittest.TestCase):
    def test_length_and_type(self):
        for size in [0, 1, 16, 32, 1024]:
            with self.subTest(size=size):
                data = generate_random_bytes(size)
                self.assertIsInstance(data, bytes)
                self.assertEqual(len(data), size)

    def test_negative_length(self):
        with self.assertRaises(ValueError):
            generate_random_bytes(-1)

    def test_key_uniqueness(self):
        keys = set()

        for _ in range(1000):
            key = generate_random_bytes(16)
            self.assertEqual(len(key), 16)
            self.assertNotIn(key, keys)
            keys.add(key)

        self.assertEqual(len(keys), 1000)

    def test_bit_distribution(self):
        data = generate_random_bytes(16 * 1000)
        ones = sum(bin(byte).count("1") for byte in data)
        proportion = ones / (len(data) * 8)

        self.assertGreaterEqual(proportion, 0.48)
        self.assertLessEqual(proportion, 0.52)

    def test_random_source_error(self):
        with patch(
            "cryptocore.csprng.os.urandom",
            side_effect=OSError("Источник случайности недоступен"),
        ):
            with self.assertRaisesRegex(
                OSError,
                "Не удалось получить случайные байты",
            ):
                generate_random_bytes(16)


if __name__ == "__main__":
    unittest.main()