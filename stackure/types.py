"""Data types returned by the Stackure SDK."""

from dataclasses import dataclass, field


@dataclass
class StackureUser:
    """Authenticated user information returned from Stackure.

    Attributes:
        user_id: Unique identifier for the user.
        user_email: User's email address.
        user_first_name: User's first name.
        user_last_name: User's last name.
        user_roles: List of role names assigned to the user.
    """

    user_id: str
    user_email: str
    user_first_name: str
    user_last_name: str
    user_roles: list[str] = field(default_factory=list)


@dataclass
class MagicLinkResponse:
    """Response from a magic-link send request.

    Attributes:
        message: Human-readable status message from the API.
        token: Verification token returned in local/testing environments only.
    """

    message: str
    token: str | None = None


@dataclass
class SessionValidationResponse:
    """Response from a session validation request.

    Attributes:
        authenticated: Whether the session is currently valid.
        user: Authenticated user details. Present only when ``authenticated`` is ``True``.
        sign_in_url: Redirect URL for unauthenticated users to initiate sign-in.
    """

    authenticated: bool
    user: StackureUser | None = None
    sign_in_url: str | None = None
