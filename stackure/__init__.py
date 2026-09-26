"""Stackure is the Python SDK for the Stackure authentication API.

Stackure provides passwordless B2B authentication. This SDK wraps the public
API behind six free functions and a middleware.

Quickstart
----------

Protect an ASGI app::

    app = stackure.auth(app_id, "can_approve_invoice")(app)

Or a WSGI one::

    flask_app.wsgi_app = stackure.auth(app_id, "can_approve_invoice")(flask_app.wsgi_app)

``app_id`` is the app's UUID as registered in Stackure.

Access the authenticated user inside a view::

    user = stackure.user_from_request(request)

Manual verification without middleware::

    result = stackure.verify(app_id, request)
    if result.authenticated:
        ...  # use result.user

Send a magic-link email::

    stackure.send_magic_link("user@example.com", app_id)

Log the user out::

    r = stackure.logout(request)

Sign-in handoff
---------------

Stackure's session cookie is scoped to the Stackure host and is never visible
to your app. After a successful magic-link sign-in, Stackure hands the browser
back to the app's registered URL with a ``session_token`` POST form field: an
app-scoped session token valid only for this app, accepted by the validate
endpoint for your app ID and never by Stackure itself.

The middleware consumes it automatically: it validates the token, stores it in
a ``stackure_session`` cookie on your own domain (not ``session``, which Flask
uses for its own session) and redirects to the same URL as a GET. Invalid
tokens are ignored, and handoff bodies over 4 KB are ignored.

Session binding
---------------

Sessions are not bound to the browser's user agent or IP address. The SDK
still forwards the original ``User-Agent`` and ``X-Forwarded-For`` on every
validation call, but they are informational only; validation does not depend
on them.

Every request with a session token is validated against Stackure, so revoking
a session takes effect immediately. Requests without a well-formed token get
the sign-in URL without a Stackure call.

Content negotiation
-------------------

The middleware inspects the ``Accept`` header. Browser requests (``Accept:
text/html``) redirect to the sign-in URL on 401. API requests (``Accept:
application/json``) receive a JSON error body.

Configuration
-------------

``STACKURE_APP_SECRET`` must be set to the app secret shown when the app was
registered (or last rotated) in Stackure. It is sent as the ``X-App-Secret``
header on every call; the first call that actually reaches Stackure raises a
``"validation"`` :class:`StackureError` when it is missing.
``STACKURE_BASE_URL`` overrides the API host (default
``https://stackure.com``).

A newly registered app is not usable by anyone, even its creator, until it is
shared with the organization or assigned to a team in Stackure. Do that before
testing sign-in.

Every call has one 2-second deadline covering connect, headers, body and the
single retry. Calls retry once after 500 ms on a 5xx or a connection failure,
never on a timeout. A timeout anywhere, including while reading the body,
surfaces as ``"timeout"``.

Errors
------

Every function except :func:`verify` raises :class:`StackureError`. Inspect
``code`` to branch on category: ``"validation"``, ``"auth"``, ``"forbidden"``,
``"timeout"``, ``"network"``.

Releases
--------

Releases are cut from main automatically and versioned ``v1.YYYYMMDD.N``. Each
one carries a GitHub build-provenance attestation and publishes to PyPI via
OIDC trusted publishing.
"""

from .client import send_magic_link, validate_session
from .errors import StackureError, StackureErrorCode
from .middleware import auth, logout, to_request, user_from_request, verify
from .types import (
    MagicLinkResponse,
    Redirect,
    Request,
    Session,
    User,
    VerifyError,
    VerifyResult,
)

__all__ = [
    "auth",
    "verify",
    "logout",
    "user_from_request",
    "send_magic_link",
    "validate_session",
    "to_request",
    "Request",
    "User",
    "Session",
    "VerifyError",
    "VerifyResult",
    "MagicLinkResponse",
    "Redirect",
    "StackureError",
    "StackureErrorCode",
]
