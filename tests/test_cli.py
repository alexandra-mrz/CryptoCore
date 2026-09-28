import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


class TestCLI(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)

        self.folder = Path(self.temp_dir.name)
        self.input_file = self.folder / "input.bin"
        self.output_file = self.folder / "encrypted.bin"

        self.input_file.write_bytes(bytes(range(256)))

        self.arguments = [
            "--algorithm", "aes",
            "--mode", "ecb",
            "--encrypt",
            "--key", "000102030405060708090a0b0c0d0e0f",
            "--input", str(self.input_file),
            "--output", str(self.output_file),
        ]

    def run_cli(self, arguments):
        return subprocess.run(
            [sys.executable, "-m", "cryptocore"] + arguments,
            capture_output=True,
        )

    def assert_cli_error(self, arguments):
        result = self.run_cli(arguments)
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(result.stderr)

    def test_file_round_trip(self):
        result = self.run_cli(self.arguments)
        self.assertEqual(result.returncode, 0, result.stderr)

        decrypted_file = self.folder / "decrypted.bin"
        arguments = self.arguments.copy()
        arguments[arguments.index("--encrypt")] = "--decrypt"
        arguments[arguments.index("--input") + 1] = str(self.output_file)
        arguments[arguments.index("--output") + 1] = str(decrypted_file)

        result = self.run_cli(arguments)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            self.input_file.read_bytes(),
            decrypted_file.read_bytes(),
        )

    def test_missing_arguments(self):
        self.assert_cli_error([])

    def test_conflicting_operations(self):
        self.assert_cli_error(self.arguments + ["--decrypt"])

    def test_missing_operation(self):
        arguments = self.arguments.copy()
        arguments.remove("--encrypt")
        self.assert_cli_error(arguments)

    def test_invalid_key(self):
        for key in ["1234", "z" * 32]:
            with self.subTest(key=key):
                arguments = self.arguments.copy()
                arguments[arguments.index("--key") + 1] = key
                self.assert_cli_error(arguments)

    def test_unsupported_algorithm_and_mode(self):
        for option, value in [
            ("--algorithm", "des"),
            ("--mode", "cbc"),
        ]:
            with self.subTest(option=option):
                arguments = self.arguments.copy()
                arguments[arguments.index(option) + 1] = value
                self.assert_cli_error(arguments)

    def test_missing_input_file(self):
        arguments = self.arguments.copy()
        arguments[arguments.index("--input") + 1] = str(
            self.folder / "missing.bin"
        )
        self.assert_cli_error(arguments)

    def test_output_write_error(self):
        arguments = self.arguments.copy()
        arguments[arguments.index("--output") + 1] = str(
            self.folder / "missing_folder" / "output.bin"
        )
        self.assert_cli_error(arguments)


if __name__ == "__main__":
    unittest.main()