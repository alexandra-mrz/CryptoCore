from Crypto.Cipher import AES

from cryptocore.modes.ecb import BLOCK_SIZE, add_padding, remove_padding


def cbc_encrypt(data, key, iv):
    if len(key) != 16:
        raise ValueError("Ключ AES-128 должен содержать 16 байт.")

    if len(iv) != BLOCK_SIZE:
        raise ValueError("IV должен содержать 16 байт.")

    cipher = AES.new(key, AES.MODE_ECB)
    padded_data = add_padding(data)
    result = bytearray()
    previous_block = iv

    for position in range(0, len(padded_data), BLOCK_SIZE):
        block = padded_data[position:position + BLOCK_SIZE]

        mixed_block = bytes(
            block[i] ^ previous_block[i]
            for i in range(BLOCK_SIZE)
        )

        encrypted_block = cipher.encrypt(mixed_block)
        result.extend(encrypted_block)
        previous_block = encrypted_block

    return bytes(result)


def cbc_decrypt(data, key, iv):
    if len(key) != 16:
        raise ValueError("Ключ AES-128 должен содержать 16 байт.")

    if len(iv) != BLOCK_SIZE:
        raise ValueError("IV должен содержать 16 байт.")

    if not data or len(data) % BLOCK_SIZE != 0:
        raise ValueError(
            "Шифротекст должен быть непустым и иметь длину, кратную 16 байтам."
        )

    cipher = AES.new(key, AES.MODE_ECB)
    result = bytearray()
    previous_block = iv

    for position in range(0, len(data), BLOCK_SIZE):
        block = data[position:position + BLOCK_SIZE]
        decrypted_block = cipher.decrypt(block)

        plain_block = bytes(
            decrypted_block[i] ^ previous_block[i]
            for i in range(BLOCK_SIZE)
        )

        result.extend(plain_block)
        previous_block = block

    return remove_padding(bytes(result))