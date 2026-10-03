from Crypto.Cipher import AES

from cryptocore.modes.ecb import BLOCK_SIZE


def ofb_encrypt(data, key, iv):
    if len(key) != 16:
        raise ValueError("Ключ AES-128 должен содержать 16 байт.")

    if len(iv) != BLOCK_SIZE:
        raise ValueError("IV должен содержать 16 байт.")

    cipher = AES.new(key, AES.MODE_ECB)
    result = bytearray()
    feedback = iv

    for position in range(0, len(data), BLOCK_SIZE):
        block = data[position:position + BLOCK_SIZE]
        feedback = cipher.encrypt(feedback)

        encrypted_block = bytes(
            block[i] ^ feedback[i]
            for i in range(len(block))
        )

        result.extend(encrypted_block)

    return bytes(result)


def ofb_decrypt(data, key, iv):
    return ofb_encrypt(data, key, iv)