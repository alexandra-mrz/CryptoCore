import argparse
import sys

from cryptocore.file_io import read_binary, write_binary
from cryptocore.modes.ecb import ecb_encrypt, ecb_decrypt
from cryptocore.modes.cbc import cbc_encrypt, cbc_decrypt
from cryptocore.modes.cfb import cfb_encrypt, cfb_decrypt
from cryptocore.modes.ofb import ofb_encrypt, ofb_decrypt
from cryptocore.modes.ctr import ctr_encrypt, ctr_decrypt
from cryptocore.csprng import generate_random_bytes


def build_parser():
    parser = argparse.ArgumentParser(
        prog="cryptocore",
        description="Шифрование и расшифрование файлов AES-128.",
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
        choices=["ecb", "cbc", "cfb", "ofb", "ctr"],
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
        help="ключ AES-128: 32 HEX-символа; при шифровании без ключа он генерируется автоматически",
    )

    parser.add_argument(
        "--iv",
        help="IV: 32 HEX-символа, только для расшифрования новых режимов",
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


def parse_iv(hex_iv):
    if len(hex_iv) != 32:
        raise ValueError("IV должен содержать ровно 32 HEX-символа.")

    for symbol in hex_iv:
        if symbol not in "0123456789abcdefABCDEF":
            raise ValueError(
                "IV должен содержать только цифры 0–9 и буквы a–f."
            )

    return bytes.fromhex(hex_iv)


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        if args.key is None and args.decrypt:
            raise ValueError("--key обязателен при расшифровании.")

        key = parse_key(args.key) if args.key is not None else None

        if args.iv is not None and args.encrypt:
            raise ValueError("--iv нельзя указывать при шифровании.")

        if args.iv is not None and args.mode == "ecb":
            raise ValueError("Режим ECB не использует IV.")

        iv = parse_iv(args.iv) if args.iv is not None else None
    except ValueError as error:
        print(f"Ошибка: {error}", file=sys.stderr)
        return 2

    if key is not None:
        repeated_bytes = len(set(key)) == 1
        sequential_bytes = all(
            key[i] == (key[0] + i) % 256
            for i in range(len(key))
        )

        if repeated_bytes or sequential_bytes:
            print(
                "Предупреждение: ключ содержит повторяющиеся "
                "или последовательные байты и выглядит слабым.",
                file=sys.stderr,
            )

    encrypt_functions = {
        "cbc": cbc_encrypt,
        "cfb": cfb_encrypt,
        "ofb": ofb_encrypt,
        "ctr": ctr_encrypt,
    }

    decrypt_functions = {
        "cbc": cbc_decrypt,
        "cfb": cfb_decrypt,
        "ofb": ofb_decrypt,
        "ctr": ctr_decrypt,
    }

    try:
        data = read_binary(args.input_file)

        if key is None:
            key = generate_random_bytes(16)
            print(f"[INFO] Generated random key: {key.hex()}", flush=True)

        if args.mode == "ecb":
            if args.encrypt:
                result = ecb_encrypt(data, key)
            else:
                result = ecb_decrypt(data, key)

        elif args.encrypt:
            iv = generate_random_bytes(16)
            encrypted = encrypt_functions[args.mode](data, key, iv)
            result = iv + encrypted

        else:
            if iv is None:
                if len(data) < 16:
                    raise ValueError(
                        "Файл слишком короткий: отсутствует полный IV "
                        "длиной 16 байт."
                    )

                iv = data[:16]
                data = data[16:]

            result = decrypt_functions[args.mode](data, key, iv)

        write_binary(args.output_file, result)
    except (OSError, ValueError) as error:
        print(f"Ошибка: {error}", file=sys.stderr)
        return 1

    return 0