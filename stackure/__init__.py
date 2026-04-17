"""Stackure Python SDK for authentication and session management.

Four public entry points:

* :func:`auth` — decorator that enforces authentication on a view
* :func:`verify` — non-throwing check that returns a :class:`VerifyResult`
* :func:`send_magic_link` — trigger a magic-link sign-in email
* :func:`logout` — revoke a session

Plus the supporting types :class:`User`, :class:`VerifyResult`,
:class:`MagicLinkResponse`, and the single error type :class:`StackureError`.

Example:
    >>> import stackure
    >>> await stackure.send_magic_link(email="user@example.com", app_id="...")
"""

from .client import logout, send_magic_link
from .errors import StackureError
from .middleware import auth, verify
from .types import MagicLinkResponse, User, VerifyResult

__all__ = [
    "auth",
    "verify",
    "send_magic_link",
    "logout",
    "User",
    "VerifyResult",
    "MagicLinkResponse",
    "StackureError",
]
