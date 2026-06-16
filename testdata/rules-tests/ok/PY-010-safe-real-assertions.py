# PY-010 SAFE: real assertions with conditions, not tautologies
# Also: abstract base class with NotImplementedError is fine
from abc import ABC, abstractmethod
from typing import Any, Optional


class BaseAuthProvider(ABC):
    """Abstract base — NotImplementedError here is legitimate."""

    @abstractmethod
    def authenticate(self, username: str, password: str) -> bool:
        raise NotImplementedError("Subclasses must implement authenticate()")  # SAFE: ABC

    @abstractmethod
    def verify_token(self, token: str) -> Optional[dict]:
        raise NotImplementedError("Subclasses must implement verify_token()")  # SAFE: ABC


def validate_config(config: dict) -> None:
    """Validate application configuration at startup."""
    assert "secret_key" in config, "secret_key is required in config"       # SAFE: real condition
    assert len(config["secret_key"]) >= 32, "secret_key must be >= 32 chars"  # SAFE: real condition
    assert "db_url" in config, "db_url is required in config"                 # SAFE: real condition


def check_environment() -> bool:
    """Check environment variables are set."""
    import os
    required = ["DB_PASSWORD", "JWT_SECRET", "REDIS_URL"]
    missing = [var for var in required if not os.environ.get(var)]
    assert not missing, f"Missing required env vars: {missing}"  # SAFE: real condition
    return True
