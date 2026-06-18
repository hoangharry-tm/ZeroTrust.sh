import os


BASE_DIR = "/var/app/data"


def read_safe(filename):
    safe_path = os.path.join(BASE_DIR, filename)
    real = os.path.realpath(safe_path)
    if not real.startswith(BASE_DIR):
        raise ValueError("path traversal detected")
    with open(real) as f:
        return f.read()


def delete_safe(filepath):
    real = os.path.realpath(filepath)
    if not real.startswith(BASE_DIR):
        raise ValueError("invalid path")
    os.remove(real)
