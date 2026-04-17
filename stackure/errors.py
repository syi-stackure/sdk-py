"""Stackure SDK error type."""


class StackureError(Exception):
    """The single exception type raised by every SDK function.

    Catch once and inspect ``code`` to branch on category.

    Attributes:
        code: One of ``"validation"``, ``"auth"``, ``"forbidden"``, ``"timeout"``,
            ``"network"``.
        status_code: HTTP status returned by the API, or ``None`` if the error
            happened before a response was received.

    Example:
        >>> try:
        ...     await send_magic_link(email="bad")
        ... except StackureError as err:
        ...     if err.code == "validation":
        ...         ...
    """

    def __init__(self, code: str, message: str, status_code: int | None = None):
        super().__init__(message)
        self.code = code
        self.status_code = status_code
