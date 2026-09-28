def read_binary(path):
    with open(path, "rb") as file:
        return file.read()


def write_binary(path, data):
    with open(path, "wb") as file:
        file.write(data)