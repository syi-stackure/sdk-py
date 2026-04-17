"""Data types returned by the Stackure SDK."""

from dataclasses import dataclass, field


@dataclass
class User:
    """An authenticated Stackure user.

    Attributes:
        user_id: Unique identifier for the user.
        user_email: User's email address.
        user_first_name: User's first name.
        user_last_name: User's last name.
        user_roles: Role names assigned to the user for the current app.
    """

    user_id: str
    user_email: str
    user_first_name: str
    user_last_name: str
    user_roles: list[str] = field(default_factory=list)


@dataclass
class MagicLinkResponse:
    """Successful :func:`send_magic_link` response.

    Attributes:
        message: Human-readable confirmation string from the API.
    """

    message: str


@dataclass
class VerifyResult:
    """Outcome of a :func:`verify` call.

    Exactly one of ``user`` or ``error`` is populated depending on
    ``authenticated``.

    Attributes:
        authenticated: Whether the request carries a valid session.
        user: Authenticated user when ``authenticated`` is ``True``.
        error: Dict with ``code`` (int), ``message`` (str), and optional
            ``sign_in_url`` when ``authenticated`` is ``False``.
    """

    authenticated: bool
    user: User | None = None
    error: dict | None = None
