import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


class TestKeyGeneration(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)

        self.folder = Path(self.temp_dir.name)
        self.input_file = self.folder / "input.bin"
        self.encrypted_file = self.folder / "encrypted.bin"
        self.decrypted_file = self.folder / "decrypted.bin"

        self.data = bytes(range(255))
        self.input_file.write_bytes(self.data)
        self.modes = ["ecb", "cbc", "cfb", "ofb", "ctr"]

    def run_cli(self, mode, operation, input_file, output_file, key=None):
        arguments = [
            sys.executable, "-m", "cryptocore",
            "--algorithm", "aes",
            "--mode", mode,
            operation,
            "--input", str(input_file),
            "--output", str(output_file),
        ]

        if key is not None:
            arguments.extend(["--key", key])

        return subprocess.run(arguments, capture_output=True)

    def test_generated_key_round_trip(self):
        for mode in self.modes:
            with self.subTest(mode=mode):
                result = self.run_cli(
                    mode, "--encrypt",
                    self.input_file, self.encrypted_file,
                )
                self.assertEqual(result.returncode, 0, result.stderr)

                lines = result.stdout.decode("ascii").splitlines()
                self.assertEqual(len(lines), 1)

                prefix = "[INFO] Generated random key: "
                self.assertTrue(lines[0].startswith(prefix))

                key = lines[0][len(prefix):]
                self.assertRegex(key, r"^[0-9a-f]{32}$")

                result = self.run_cli(
                    mode, "--decrypt",
                    self.encrypted_file, self.decrypted_file,
                    key=key,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, b"")
                self.assertEqual(
                    self.decrypted_file.read_bytes(),
                    self.data,
                )

                if mode == "ecb":
                    expected_size = 256
                elif mode == "cbc":
                    expected_size = 16 + 256
                else:
                    expected_size = 16 + len(self.data)

                self.assertEqual(
                    self.encrypted_file.stat().st_size,
                    expected_size,
                )

    def test_decryption_requires_key(self):
        for mode in self.modes:
            with self.subTest(mode=mode):
                result = self.run_cli(
                    mode, "--decrypt",
                    self.input_file, self.decrypted_file,
                )
                self.assertEqual(result.returncode, 2)
                self.assertTrue(result.stderr)
                self.assertEqual(result.stdout, b"")
                self.assertFalse(self.decrypted_file.exists())

    def test_explicit_key_is_not_printed(self):
        key = "a738c109f45b268de0937ac2518fb604"

        for mode in self.modes:
            with self.subTest(mode=mode):
                result = self.run_cli(
                    mode, "--encrypt",
                    self.input_file, self.encrypted_file,
                    key=key,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, b"")
                self.assertEqual(result.stderr, b"")

    def test_weak_key_warning(self):
        keys = [
            "00000000000000000000000000000000",
            "000102030405060708090a0b0c0d0e0f",
        ]

        for key in keys:
            with self.subTest(key=key):
                result = self.run_cli(
                    "ecb", "--encrypt",
                    self.input_file, self.encrypted_file,
                    key=key,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertTrue(result.stderr)
                self.assertEqual(result.stdout, b"")


if __name__ == "__main__":
    unittest.main()