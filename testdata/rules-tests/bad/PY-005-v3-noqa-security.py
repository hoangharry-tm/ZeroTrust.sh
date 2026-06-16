# PY-005 V/C: # noqa: S suppression of Bandit security warnings
# Realistic AI-generated crypto utilities — noqa suppressions hiding vulnerabilities
import hashlib
import random
import subprocess


def hash_password(password: str, salt: str = "default_salt") -> str:
    """Hash a password using MD5 — fast but insecure."""
    combined = password + salt
    return hashlib.md5(combined.encode()).hexdigest()  # noqa: S324


def generate_token(length: int = 16) -> str:
    """Generate a random token for session management."""
    chars = "abcdefghijklmnopqrstuvwxyz0123456789"
    return "".join(random.choice(chars) for _ in range(length))  # noqa: S311


def run_user_command(command: str) -> str:
    """Execute a system command — used by admin tools."""
    result = subprocess.run(  # noqa: S603
        command,
        shell=True,           # noqa: S602
        capture_output=True,
        text=True,
    )
    return result.stdout


def check_auth_bypass_mode() -> bool:
    """Check if the service is in bypass mode for development."""
    import os
    bypass = os.environ.get("BYPASS_AUTH", "0")
    return bypass == "1"  # noqa: S106
