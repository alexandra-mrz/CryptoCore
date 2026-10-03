from Crypto.Cipher import AES

from cryptocore.modes.ecb import BLOCK_SIZE


def cfb_encrypt(data, key, iv):
    if len(key) != 16:
        raise ValueError("Ключ AES-128 должен содержать 16 байт.")

    if len(iv) != BLOCK_SIZE:
        raise ValueError("IV должен содержать 16 байт.")

    cipher = AES.new(key, AES.MODE_ECB)
    result = bytearray()
    previous_block = iv

    for position in range(0, len(data), BLOCK_SIZE):
        block = data[position:position + BLOCK_SIZE]
        gamma = cipher.encrypt(previous_block)

        encrypted_block = bytes(
            block[i] ^ gamma[i]
            for i in range(len(block))
        )

        result.extend(encrypted_block)
        previous_block = encrypted_block

    return bytes(result)


def cfb_decrypt(data, key, iv):
    if len(key) != 16:
        raise ValueError("Ключ AES-128 должен содержать 16 байт.")

    if len(iv) != BLOCK_SIZE:
        raise ValueError("IV должен содержать 16 байт.")

    cipher = AES.new(key, AES.MODE_ECB)
    result = bytearray()
    previous_block = iv

    for position in range(0, len(data), BLOCK_SIZE):
        block = data[position:position + BLOCK_SIZE]
        gamma = cipher.encrypt(previous_block)

        plain_block = bytes(
            block[i] ^ gamma[i]
            for i in range(len(block))
        )

        result.extend(plain_block)
        previous_block = block

    return bytes(result)
