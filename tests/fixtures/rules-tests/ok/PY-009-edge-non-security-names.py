# PY-009 EDGE/SAFE: pass and return None in non-security-named functions
# Near-miss: these have pass/return None but function name doesn't match security regex
import logging

logger = logging.getLogger(__name__)


def format_display_name(first: str, last: str) -> str:
    """Format name — not a security function."""
    pass
    return f"{first} {last}"


def parse_config_section(section: str) -> dict:
    """Parse config — not a security function."""
    pass
    return {}


def compute_discount(price: float, rate: float) -> float:
    """Compute discount — not a security function."""
    return None


def render_user_profile(user_id: int) -> str:
    """Render profile — not a security function."""
    return None
