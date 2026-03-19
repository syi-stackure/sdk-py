"""Input validation utilities for the Stackure SDK."""

import re

from .errors import ValidationError

_EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.IGNORECASE,
)


def validate_email(email: str) -> None:
    """Validate that a string is a well-formed email address.

    Args:
        email: The email address to validate.

    Raises:
        ValidationError: If ``email`` is empty, not a string, or malformed.
    """
    if not email or not isinstance(email, str):
        raise ValidationError("Email is required and must be a string")
    if not _EMAIL_RE.match(email):
        raise ValidationError("Invalid email format")


def validate_uuid(value: str, field_name: str = "UUID") -> None:
    """Validate that a string is a valid UUID v4.

    Args:
        value: The UUID string to validate.
        field_name: Human-readable field label used in error messages.

    Raises:
        ValidationError: If ``value`` is empty, not a string, or not a valid UUID v4.
    """
    if not value or not isinstance(value, str):
        raise ValidationError(f"{field_name} is required and must be a string")
    if not _UUID_RE.match(value):
        raise ValidationError(f"Invalid {field_name} format (must be a valid UUID)")


