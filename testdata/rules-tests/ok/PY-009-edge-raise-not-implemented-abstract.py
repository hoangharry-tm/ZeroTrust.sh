# PY-009 EDGE/SAFE: raise NotImplementedError in abstract base class — legitimate pattern
# AbstractBaseClass stub should NOT fire (ABC is excluded in PY-010 but let's verify PY-009)
from abc import ABC, abstractmethod
from typing import Any


class BaseInputValidator(ABC):
    """Abstract base class for all input validators."""

    @abstractmethod
    def validate(self, value: Any) -> bool:
        """Validate the input value. Must be implemented by subclasses."""
        raise NotImplementedError("Subclasses must implement validate()")

    @abstractmethod
    def sanitize(self, value: str) -> str:
        """Sanitize the input value. Must be implemented by subclasses."""
        raise NotImplementedError("Subclasses must implement sanitize()")


class EmailValidator(BaseInputValidator):
    """Concrete email validator."""

    def validate(self, value: Any) -> bool:
        import re
        if not isinstance(value, str):
            return False
        return bool(re.match(r"^[^@]+@[^@]+\.[^@]+$", value))

    def sanitize(self, value: str) -> str:
        return value.strip().lower()[:254]


class PhoneValidator(BaseInputValidator):
    """Concrete phone number validator."""

    def validate(self, value: Any) -> bool:
        import re
        if not isinstance(value, str):
            return False
        digits_only = re.sub(r"[\s\-\(\)\+]", "", value)
        return digits_only.isdigit() and 7 <= len(digits_only) <= 15

    def sanitize(self, value: str) -> str:
        import re
        return re.sub(r"[^\d\+\-\(\)\s]", "", value)
