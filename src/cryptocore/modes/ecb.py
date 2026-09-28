from Crypto.Cipher import AES


BLOCK_SIZE = 16


def add_padding(data):
    padding_size = BLOCK_SIZE - len(data) % BLOCK_SIZE
    return data + bytes([padding_size]) * padding_size


def remove_padding(data):
    if not data or len(data) % BLOCK_SIZE != 0:
        raise ValueError("Некорректная длина данных с padding.")

    padding_size = data[-1]

    if padding_size < 1 or padding_size > BLOCK_SIZE:
        raise ValueError("Некорректный padding PKCS#7.")

    if data[-padding_size:] != bytes([padding_size]) * padding_size:
        raise ValueError("Некорректный padding PKCS#7.")

    return data[:-padding_size]


def ecb_encrypt(data, key):
    if len(key) != 16:
        raise ValueError("Ключ AES-128 должен содержать 16 байт.")

    cipher = AES.new(key, AES.MODE_ECB)
    padded_data = add_padding(data)
    result = bytearray()

    for position in range(0, len(padded_data), BLOCK_SIZE):
        block = padded_data[position:position + BLOCK_SIZE]
        result.extend(cipher.encrypt(block))

    return bytes(result)


def ecb_decrypt(data, key):
    if len(key) != 16:
        raise ValueError("Ключ AES-128 должен содержать 16 байт.")

    if not data or len(data) % BLOCK_SIZE != 0:
        raise ValueError(
            "Шифротекст должен быть непустым и иметь длину, кратную 16 байтам."
        )

    cipher = AES.new(key, AES.MODE_ECB)
    result = bytearray()

    for position in range(0, len(data), BLOCK_SIZE):
        block = data[position:position + BLOCK_SIZE]
        result.extend(cipher.decrypt(block))

    return remove_padding(bytes(result))