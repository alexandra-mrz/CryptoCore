from Crypto.Cipher import AES

from cryptocore.modes.ecb import BLOCK_SIZE


def ctr_encrypt(data, key, iv):
    if len(key) != 16:
        raise ValueError("Ключ AES-128 должен содержать 16 байт.")

    if len(iv) != BLOCK_SIZE:
        raise ValueError("IV должен содержать 16 байт.")

    cipher = AES.new(key, AES.MODE_ECB)
    result = bytearray()
    counter = int.from_bytes(iv, byteorder="big")

    for position in range(0, len(data), BLOCK_SIZE):
        block = data[position:position + BLOCK_SIZE]
        counter_block = counter.to_bytes(BLOCK_SIZE, byteorder="big")
        gamma = cipher.encrypt(counter_block)

        encrypted_block = bytes(
            block[i] ^ gamma[i]
            for i in range(len(block))
        )

        result.extend(encrypted_block)
        counter = (counter + 1) % (1 << 128)

    return bytes(result)


def ctr_decrypt(data, key, iv):
    return ctr_encrypt(data, key, iv)