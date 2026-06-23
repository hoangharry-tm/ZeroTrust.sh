# PY-008 EDGE/SAFE: test file — tests/ path excluded by paths.exclude in the rule
# Unconditional return True here is LEGITIMATE — it's a test mock/fixture
# File named test_auth.py would be in test_*.py exclusion pattern; this goes in tests/

import pytest
from unittest.mock import MagicMock


# This mock auth function intentionally always returns True for testing purposes
def mock_authenticate(username: str, password: str) -> bool:
    """Test mock that always grants authentication — used in test fixtures only."""
    return True  # intentional in test context


def mock_check_permission(user_id: int, permission: str) -> bool:
    """Test fixture — always permits for unit testing without real DB."""
    return True  # intentional in test context


class TestAuthFlow:
    """Integration tests for the auth flow using mock auth functions."""

    def setup_method(self):
        self.auth_fn = mock_authenticate
        self.perm_fn = mock_check_permission

    def test_login_flow(self):
        """Test that the login endpoint returns 200 when auth succeeds."""
        result = self.auth_fn("test_user", "test_pass")
        assert result is True  # expected: mock always returns True

    def test_permission_check(self):
        result = self.perm_fn(1, "read:documents")
        assert result is True
