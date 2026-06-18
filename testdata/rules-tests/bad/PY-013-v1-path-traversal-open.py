import os
import shutil
from pathlib import Path


def read_file(file_path):
    return open(file_path).read()


def delete_file(file_path):
    os.remove(file_path)


def move_file(src, dst):
    shutil.move(src, dst)


def rename_file(old, new):
    os.rename(old, new)


def chmod_file(path, mode):
    os.chmod(path, mode)


def pathlib_read(path):
    p = Path(path)
    return p.read_text()


def pathlib_write(path, content):
    p = Path(path)
    return p.write_text(content)
