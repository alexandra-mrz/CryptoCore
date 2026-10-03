import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from Crypto.Cipher import AES


class TestCLIModes(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)

        self.folder = Path(self.temp_dir.name)
        self.input_file = self.folder / "input.bin"
        self.encrypted_file = self.folder / "encrypted.bin"
        self.decrypted_file = self.folder / "decrypted.bin"

        self.key = "000102030405060708090a0b0c0d0e0f"
        self.iv = "00112233445566778899aabbccddeeff"
        self.modes = ["cbc", "cfb", "ofb", "ctr"]

    def run_cli(self, mode, operation, input_file, output_file, iv=None):
        arguments = [
            sys.executable, "-m", "cryptocore",
            "--algorithm", "aes",
            "--mode", mode,
            operation,
            "--key", self.key,
            "--input", str(input_file),
            "--output", str(output_file),
        ]

        if iv is not None:
            arguments.extend(["--iv", iv])

        return subprocess.run(arguments, capture_output=True)

    def assert_cli_error(self, result, code):
        self.assertEqual(result.returncode, code, result.stderr)
        self.assertTrue(result.stderr)

    def test_round_trip(self):
        samples = [
            b"",
            b"A" * 16,
            "Привет, мир!".encode("utf-8"),
            bytes(range(255)),
        ]

        for mode in self.modes:
            for data in samples:
                with self.subTest(mode=mode, length=len(data)):
                    self.input_file.write_bytes(data)

                    result = self.run_cli(
                        mode, "--encrypt",
                        self.input_file, self.encrypted_file,
                    )
                    self.assertEqual(result.returncode, 0, result.stderr)

                    result = self.run_cli(
                        mode, "--decrypt",
                        self.encrypted_file, self.decrypted_file,
                    )
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(self.decrypted_file.read_bytes(), data)

    def test_iv_prefix_and_explicit_iv(self):
        data = bytes(range(50))
        self.input_file.write_bytes(data)
        raw_file = self.folder / "ciphertext_only.bin"

        for mode in self.modes:
            with self.subTest(mode=mode):
                result = self.run_cli(
                    mode, "--encrypt",
                    self.input_file, self.encrypted_file,
                )
                self.assertEqual(result.returncode, 0, result.stderr)

                encrypted = self.encrypted_file.read_bytes()
                iv = encrypted[:16]
                raw_file.write_bytes(encrypted[16:])

                if mode == "cbc":
                    expected_size = 16 + (len(data) // 16 + 1) * 16
                else:
                    expected_size = 16 + len(data)

                self.assertEqual(len(encrypted), expected_size)

                result = self.run_cli(
                    mode, "--decrypt",
                    raw_file, self.decrypted_file, iv=iv.hex(),
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(self.decrypted_file.read_bytes(), data)

    def test_iv_rejected_during_encryption(self):
        self.input_file.write_bytes(b"Hello")

        for mode in self.modes:
            with self.subTest(mode=mode):
                result = self.run_cli(
                    mode, "--encrypt",
                    self.input_file, self.encrypted_file, iv=self.iv,
                )
                self.assert_cli_error(result, 2)

    def test_invalid_iv(self):
        self.input_file.write_bytes(b"A" * 32)

        for mode in self.modes:
            for iv in ["1234", "z" * 32]:
                with self.subTest(mode=mode, iv=iv):
                    result = self.run_cli(
                        mode, "--decrypt",
                        self.input_file, self.decrypted_file, iv=iv,
                    )
                    self.assert_cli_error(result, 2)

    def test_short_file_without_iv(self):
        for mode in self.modes:
            for data in [b"", b"A" * 15]:
                with self.subTest(mode=mode, length=len(data)):
                    self.input_file.write_bytes(data)

                    result = self.run_cli(
                        mode, "--decrypt",
                        self.input_file, self.decrypted_file,
                    )
                    self.assert_cli_error(result, 1)

    def test_short_ciphertext_with_explicit_iv(self):
        data = b"Hello"
        key = bytes.fromhex(self.key)
        iv = bytes.fromhex(self.iv)

        for mode in ["cfb", "ofb", "ctr"]:
            with self.subTest(mode=mode):
                if mode == "cfb":
                    cipher = AES.new(
                        key, AES.MODE_CFB, iv=iv, segment_size=128,
                    )
                elif mode == "ofb":
                    cipher = AES.new(key, AES.MODE_OFB, iv=iv)
                else:
                    cipher = AES.new(
                        key,
                        AES.MODE_CTR,
                        nonce=b"",
                        initial_value=int.from_bytes(iv, byteorder="big"),
                    )

                self.input_file.write_bytes(cipher.encrypt(data))

                result = self.run_cli(
                    mode, "--decrypt",
                    self.input_file, self.decrypted_file, iv=self.iv,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(self.decrypted_file.read_bytes(), data)

    def test_ecb_rejects_iv(self):
        self.input_file.write_bytes(b"A" * 16)

        result = self.run_cli(
            "ecb", "--decrypt",
            self.input_file, self.decrypted_file, iv=self.iv,
        )
        self.assert_cli_error(result, 2)


if __name__ == "__main__":
    unittest.main()