"""Input validation utilities for the Stackure SDK."""

import re

from .errors import StackureError

_EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.IGNORECASE,
)


def validate_email(email: str) -> None:
    """Raise a ``"validation"``-coded :class:`StackureError` if ``email`` is malformed."""
    if not email or not isinstance(email, str):
        raise StackureError("validation", "email is required")
    if not _EMAIL_RE.match(email):
        raise StackureError("validation", "invalid email format")


def validate_uuid(value: str, field_name: str = "UUID") -> None:
    """Raise a ``"validation"``-coded :class:`StackureError` if ``value`` isn't a UUID v4."""
    if not value or not isinstance(value, str):
        raise StackureError("validation", f"{field_name} is required")
    if not _UUID_RE.match(value):
        raise StackureError(
            "validation",
            f"invalid {field_name} format (must be a valid UUID)",
        )
