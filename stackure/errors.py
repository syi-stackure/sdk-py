"""Stackure SDK error type."""

from typing import Literal

StackureErrorCode = Literal["validation", "auth", "forbidden", "timeout", "network"]


class StackureError(Exception):
    """The single exception type raised by every SDK function.

    Catch once and inspect ``code`` to branch on category.

    Attributes:
        code: One of ``"validation"``, ``"auth"``, ``"forbidden"``,
            ``"timeout"``, ``"network"``.
        message: Human-readable description.
        status_code: HTTP status returned by the API, or ``None`` if the error
            happened before a response was received.

    Example:
        >>> try:
        ...     send_magic_link("bad")
        ... except StackureError as err:
        ...     if err.code == "validation":
        ...         ...
    """

    def __init__(
        self,
        code: StackureErrorCode,
        message: str,
        status_code: int | None = None,
    ) -> None:
        super().__init__(message)
        self.code: StackureErrorCode = code
        self.message = message
        self.status_code = status_code
