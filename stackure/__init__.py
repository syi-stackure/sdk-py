"""Stackure is the Python SDK for the Stackure authentication API.

Stackure provides passwordless B2B authentication. This SDK wraps the public
API behind five free functions and a middleware.

Quickstart
----------

Protect an ASGI app::

    app = stackure.auth(app_id, "view_any_app")(app)

Or a WSGI one::

    flask_app.wsgi_app = stackure.auth(app_id, "view_any_app")(flask_app.wsgi_app)

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
back to the app's registered URL with a ``session_token``, either as a POST
form field or as a query parameter.

The middleware consumes both automatically: it stores the token in a cookie on
your own domain and redirects to the same URL with the parameter stripped, so
the token does not linger in the address bar.

Session binding
---------------

Stackure binds each session to the browser's user agent and IP address.
Because the SDK validates from your server rather than the browser, it
forwards the original ``User-Agent`` and ``X-Forwarded-For`` on every
validation call. Your app must therefore see the real client IP: if it sits
behind a proxy or CDN, ensure that layer sets ``X-Forwarded-For`` correctly.

Every request is validated against Stackure, so revoking a session takes
effect immediately.

Content negotiation
-------------------

The middleware inspects the ``Accept`` header. Browser requests (``Accept:
text/html``) redirect to the sign-in URL on 401. API requests (``Accept:
application/json``) receive a JSON error body.

Configuration
-------------

The SDK has no configuration API. Point it at a non-production environment by
setting the ``STACKURE_BASE_URL`` environment variable before the first call::

    os.environ["STACKURE_BASE_URL"] = "https://stage.stackure.com"

Retry-on-5xx (one retry after 500ms) and the 2-second request timeout are
hard-coded. Timeouts are never retried.

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
