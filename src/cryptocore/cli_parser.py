import argparse
import sys

from cryptocore.file_io import read_binary, write_binary
from cryptocore.modes.ecb import ecb_encrypt, ecb_decrypt


def build_parser():
    parser = argparse.ArgumentParser(
        prog="cryptocore",
        description="Шифрование и расшифрование файлов AES-128 в режиме ECB.",
        allow_abbrev=False,
    )

    parser.add_argument(
        "--algorithm",
        required=True,
        choices=["aes"],
        help="алгоритм шифрования",
    )

    parser.add_argument(
        "--mode",
        required=True,
        choices=["ecb"],
        help="режим шифрования",
    )

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--encrypt",
        action="store_true",
        help="зашифровать файл",
    )
    group.add_argument(
        "--decrypt",
        action="store_true",
        help="расшифровать файл",
    )

    parser.add_argument(
        "--key",
        required=True,
        help="ключ AES-128: 32 шестнадцатеричных символа",
    )

    parser.add_argument(
        "--input",
        required=True,
        dest="input_file",
        help="путь к входному файлу",
    )

    parser.add_argument(
        "--output",
        required=True,
        dest="output_file",
        help="путь к выходному файлу",
    )

    return parser


def parse_key(hex_key):
    if len(hex_key) != 32:
        raise ValueError("Ключ должен содержать ровно 32 HEX-символа.")

    for symbol in hex_key:
        if symbol not in "0123456789abcdefABCDEF":
            raise ValueError(
                "Ключ должен содержать только цифры 0–9 и буквы a–f."
            )

    return bytes.fromhex(hex_key)


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        key = parse_key(args.key)
    except ValueError as error:
        print(f"Ошибка: {error}", file=sys.stderr)
        return 2

    try:
        data = read_binary(args.input_file)

        if args.encrypt:
            result = ecb_encrypt(data, key)
        else:
            result = ecb_decrypt(data, key)

        write_binary(args.output_file, result)
    except (OSError, ValueError) as error:
        print(f"Ошибка: {error}", file=sys.stderr)
        return 1

    return 0