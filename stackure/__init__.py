"""Stackure is the Python SDK for the Stackure authentication API.

Stackure provides passwordless B2B authentication. This SDK wraps the public
API behind seven free functions and two middlewares.

Quickstart
----------

Protect an ASGI app::

    app = stackure.auth()(app)

Or a WSGI one::

    flask_app.wsgi_app = stackure.auth()(flask_app.wsgi_app)

Access the authenticated user inside a view::

    user = stackure.user_from_request(request)

Manual verification without middleware::

    result = stackure.verify(request)
    if result.authenticated:
        ...  # use result.user

Send a magic-link email::

    stackure.send_magic_link("user@example.com")

Sign the user out of Stackure everywhere and clear the app's cookie, from a
route that takes every method on the logout path::

    r = stackure.logout(request)

Trigger it with a form or button that POSTs from the app's own page; a link or
any other request is sent to Stackure's sign-out page, where the user
confirms. ``logout`` is synchronous and returns a :class:`Redirect`.

List the users and teams in the caller's organization who can open the app::

    d = stackure.directory(request)

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

MCP
---

AI clients (Claude, Claude Code, VS Code, Cursor) sign users in through
Stackure and reach the app through its MCP endpoint. Protect that route with::

    app.mount("/mcp", stackure.mcp()(mcp_app))

This one line checks every MCP request in real time with the same app secret;
there is no extra setup. It reads ``Authorization: Bearer`` and ignores
cookies, so keep the MCP route outside :func:`auth`. A request that is not
signed in gets a 401 with a ``WWW-Authenticate`` header and a failed check a
503; it never redirects.

The MCP endpoint must be served from the same site as the app's registered URL
unless an MCP URL is set for the app in Stackure.

Identity facts
--------------

Every authenticated :class:`User`, from :func:`auth` or :func:`mcp`, also
carries ``user_is_app_admin``, true when the user is an app admin or owner in
their Stackure organization, in charge of its apps, and ``user_teams``, the
Stackure teams they belong to there (empty when none). Stackure defines no
in-app permissions; the app decides what these mean.

:func:`directory` returns the users and teams in the caller's organization
who can open the app, for pickers and sharing. It is authenticated by the
request's session cookie, so call it from a route behind :func:`auth`; MCP
bearer tokens are not accepted. No valid session raises ``"auth"``.

Configuration
-------------

``STACKURE_APP_ID`` must be set to the app's UUID, shown on the app page in
Stackure, and ``STACKURE_APP_SECRET`` to the app secret shown when the app was
registered (or last rotated). The secret is sent as the ``X-App-Secret`` header
on every call except sign-out; the first call that needs either raises a
``"validation"`` :class:`StackureError` when it is missing or, for the app ID,
not a UUID.
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

Every function except :func:`verify` and :func:`logout` raises
:class:`StackureError`; those two never raise. Inspect ``code`` to branch on
category: ``"validation"``, ``"auth"``, ``"forbidden"``, ``"timeout"``,
``"network"``.

Releases
--------

Releases are cut from main automatically and versioned ``v1.YYYYMMDD.N``. Each
one carries a GitHub build-provenance attestation and publishes to PyPI via
OIDC trusted publishing.
"""

from .client import send_magic_link, validate_session
from .errors import StackureError, StackureErrorCode
from .middleware import auth, directory, logout, mcp, to_request, user_from_request, verify
from .types import (
    Directory,
    DirectoryUser,
    MagicLinkResponse,
    Redirect,
    Request,
    Session,
    Team,
    User,
    VerifyError,
    VerifyResult,
)

__all__ = [
    "auth",
    "mcp",
    "verify",
    "logout",
    "user_from_request",
    "send_magic_link",
    "validate_session",
    "directory",
    "to_request",
    "Request",
    "User",
    "Session",
    "Team",
    "Directory",
    "DirectoryUser",
    "VerifyError",
    "VerifyResult",
    "MagicLinkResponse",
    "Redirect",
    "StackureError",
    "StackureErrorCode",
]
