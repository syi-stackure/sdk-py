"""Stackure Python SDK for authentication and session management.

Provides module-level convenience functions backed by a shared
:class:`~stackure.StackureClient` instance, as well as the full client
and type hierarchy for advanced usage.

Example:
    >>> import stackure
    >>> await stackure.send_magic_link(email="user@example.com", app_id="your-app-id")
"""

from .client import StackureClient
from .errors import AuthenticationError, ForbiddenError, NetworkError, StackureError, StackureTimeoutError, ValidationError
from .middleware import VerifyResult, auth, verify
from .types import MagicLinkResponse, SessionValidationResponse, StackureUser

_default_client = StackureClient()


async def send_magic_link(email: str, app_id: str | None = None) -> MagicLinkResponse:
    """Send a magic-link authentication email to a user.

    Args:
        email: Recipient's email address.
        app_id: Your Stackure application UUID.

    Returns:
        A :class:`MagicLinkResponse` with the API's status message.

    Raises:
        ValidationError: If ``email`` or ``app_id`` fails format validation.
        NetworkError: If the request fails or the API returns an error.
        StackureTimeoutError: If the request exceeds the configured timeout.
    """
    return await _default_client.send_magic_link(email, app_id)


async def validate_session(app_id: str, cookies: dict | None = None) -> SessionValidationResponse:
    """Validate the current session for an application.

    Args:
        app_id: Your Stackure application UUID.
        cookies: Session cookies from the incoming HTTP request. Pass
            ``dict(request.cookies)`` from your web framework.

    Returns:
        A :class:`SessionValidationResponse` containing authentication status
        and user details when authenticated.

    Raises:
        ValidationError: If ``app_id`` fails format validation.
        NetworkError: If the request fails or the API returns an error.
        StackureTimeoutError: If the request exceeds the configured timeout.
    """
    return await _default_client.validate_session(app_id, cookies)


async def logout(cookies: dict | None = None) -> None:
    """Sign out the current user from all Stackure applications.

    Args:
        cookies: Session cookies from the incoming HTTP request.

    Raises:
        NetworkError: If the request fails or the API returns an error.
        StackureTimeoutError: If the request exceeds the configured timeout.
    """
    return await _default_client.logout(cookies)


async def sign_in(app_id: str, email: str | None = None) -> MagicLinkResponse | None:
    """Initiate sign-in for a user.

    When ``email`` is provided, sends a magic-link directly. When omitted,
    returns ``None``; callers in browser environments should redirect to
    the ``sign_in_url`` returned by :func:`validate_session`.

    Args:
        app_id: Your Stackure application UUID.
        email: User's email address for direct magic-link delivery.

    Returns:
        A :class:`MagicLinkResponse` if ``email`` was provided, otherwise ``None``.

    Raises:
        ValidationError: If ``app_id`` or ``email`` fails format validation.
        NetworkError: If the request fails or the API returns an error.
        StackureTimeoutError: If the request exceeds the configured timeout.
    """
    return await _default_client.sign_in(app_id, email)


__all__ = [
    "StackureClient",
    "StackureError",
    "ValidationError",
    "NetworkError",
    "AuthenticationError",
    "StackureTimeoutError",
    "StackureUser",
    "MagicLinkResponse",
    "SessionValidationResponse",
    "VerifyResult",
    "auth",
    "verify",
    "send_magic_link",
    "validate_session",
    "logout",
    "sign_in",
    "ForbiddenError",
]
