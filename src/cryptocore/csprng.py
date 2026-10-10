import os


def generate_random_bytes(num_bytes: int) -> bytes:
    """Генерирует криптографически стойкие случайные байты."""
    if num_bytes < 0:
        raise ValueError("Количество байтов не может быть отрицательным.")

    try:
        return os.urandom(num_bytes)
    except OSError as error:
        raise OSError(
            "Не удалось получить случайные байты от операционной системы."
        ) from error