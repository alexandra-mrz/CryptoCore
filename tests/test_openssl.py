import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


class TestOpenSSL(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.openssl = shutil.which("openssl")
        if cls.openssl is None:
            raise RuntimeError(
                "OpenSSL не найден. Добавьте его папку в PATH."
            )

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)

        self.folder = Path(self.temp_dir.name)
        self.original = self.folder / "original.bin"
        self.encrypted = self.folder / "encrypted.bin"
        self.raw_ciphertext = self.folder / "ciphertext_only.bin"
        self.decrypted = self.folder / "decrypted.bin"

        self.key = "000102030405060708090a0b0c0d0e0f"
        self.iv = "00112233445566778899aabbccddeeff"
        self.modes = ["cbc", "cfb", "ofb", "ctr"]
        self.samples = [b"", b"A" * 16, bytes(range(255))]

    def run_command(self, command):
        result = subprocess.run(command, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_cryptocore_to_openssl(self):
        for mode in self.modes:
            for data in self.samples:
                with self.subTest(mode=mode, length=len(data)):
                    self.original.write_bytes(data)

                    self.run_command([
                        sys.executable, "-m", "cryptocore",
                        "--algorithm", "aes",
                        "--mode", mode,
                        "--encrypt",
                        "--key", self.key,
                        "--input", str(self.original),
                        "--output", str(self.encrypted),
                    ])

                    encrypted = self.encrypted.read_bytes()
                    self.assertGreaterEqual(len(encrypted), 16)

                    iv = encrypted[:16].hex()
                    self.raw_ciphertext.write_bytes(encrypted[16:])

                    self.run_command([
                        self.openssl, "enc",
                        f"-aes-128-{mode}",
                        "-d",
                        "-K", self.key,
                        "-iv", iv,
                        "-in", str(self.raw_ciphertext),
                        "-out", str(self.decrypted),
                    ])

                    self.assertEqual(self.decrypted.read_bytes(), data)

    def test_openssl_to_cryptocore(self):
        for mode in self.modes:
            for data in self.samples:
                with self.subTest(mode=mode, length=len(data)):
                    self.original.write_bytes(data)

                    self.run_command([
                        self.openssl, "enc",
                        f"-aes-128-{mode}",
                        "-e",
                        "-K", self.key,
                        "-iv", self.iv,
                        "-in", str(self.original),
                        "-out", str(self.encrypted),
                    ])

                    self.run_command([
                        sys.executable, "-m", "cryptocore",
                        "--algorithm", "aes",
                        "--mode", mode,
                        "--decrypt",
                        "--key", self.key,
                        "--iv", self.iv,
                        "--input", str(self.encrypted),
                        "--output", str(self.decrypted),
                    ])

                    self.assertEqual(self.decrypted.read_bytes(), data)


if __name__ == "__main__":
    unittest.main()