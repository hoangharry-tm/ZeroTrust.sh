import os
from pathlib import Path
BASE = Path("/var/templates")
def read_template(name: str) -> str:
    path = (BASE / name).resolve()
    if not str(path).startswith(str(BASE)):
        raise PermissionError("path traversal denied")
    return path.read_text()
