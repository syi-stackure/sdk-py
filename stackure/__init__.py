"""Stackure is the Python SDK for the Stackure authentication API.

Stackure provides sign-in and app access for your people and your partners.
This SDK wraps the public API behind 9 free functions and 2 middlewares.

Quickstart
----------

Protect an ASGI app::

    app = stackure.auth()(app)

Or a WSGI one::

    flask_app.wsgi_app = stackure.auth()(flask_app.wsgi_app)

Or only some routes, here ``/admin`` and everything under it::

    app = stackure.auth("/admin")(app)

Access the authenticated user inside a view::

    user = stackure.user_from_request(request)

Manual verification without middleware::

    result = stackure.verify(request)
    if result.authenticated:
        ...  # use result.user

Send a magic-link email::

    stackure.send_magic_link("user@example.com")

Sign the user out of Stackure everywhere and clear the app's cookie, from a
route that takes every method on the sign-out path::

    r = stackure.logout(request)

Trigger it with a form or button that POSTs from the app's own page; a link or
any other request is sent to Stackure's sign-out page, where the user
confirms. ``logout`` is synchronous and returns a :class:`Redirect`.

List the users in the caller's organization who can open the app, and the
teams that have it, one page at a time::

    page = stackure.directory_users(request, query="ada")
    teams = stackure.directory_teams(request)

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

Sessions are not bound to the browser's user agent or IP address. On every
call it makes for a request, the SDK still forwards the browser's
``User-Agent`` and sends its IP address in ``Stackure-Client-IP``: the first
``X-Forwarded-For`` entry, else the connection's address. They are
informational only; validation does not depend on them.

Every request with a session token is validated against Stackure, so revoking
a session takes effect immediately. Requests without a well-formed token get
the sign-in URL without a Stackure call, except under ``auth()`` on localhost,
where the sign-in URL comes from Stackure.

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

:func:`directory_users` and :func:`directory_teams` return the users in the
caller's organization who can open the app and the teams that have it, for
pickers and sharing. Each call returns a :class:`DirectoryPage`, sorted by
name: ``query`` searches, ``limit`` sets the page size (100 by default, 200 at
most) and ``next_cursor``, passed back as ``cursor``, gets the next page.
``total`` is set on the first page when there are 10,000 matches or fewer.
``ids`` returns only those IDs that can open the app, up to 200, to check or
name people and teams you already store.
Both are authenticated by the request's session cookie, so call them from a
route behind :func:`auth`; MCP bearer tokens are not accepted. No valid session
raises ``"auth"``.

Closed organizations
--------------------

When an organization closes in Stackure, every app it used that another
organization added is asked to delete what it stores for it and for the
organizations under it. Register one function to do that::

    @stackure.on_org_closed
    def delete_org(account_id):
        db.delete_org(account_id)

``account_id`` is the closed organization's ID, the same value as
``User.account_id``. There is no scheduled job, endpoint or setting to add.
The SDK checks once when :func:`on_org_closed` is called, and Stackure reports
new closures on the session checks the SDK already makes. The SDK then runs
the function in a background thread, once for each closed organization, and
tells Stackure each one is done when the function returns.

It can also be an ``async`` function. It then runs on the app's event loop,
the one serving requests through :func:`auth` or :func:`mcp`, so it can use
what the app set up at startup, such as a database pool. Before the first such
request, the SDK uses the loop :func:`on_org_closed` was called from, such as
the app's lifespan. Registered with no running loop, such as at import, it
waits for the first session check. With no loop serving requests, as in a WSGI
app, the SDK runs it in that thread with :func:`asyncio.run`.

The same organization can arrive again, for example when the app stops
between deleting and telling Stackure, so the function must also succeed when
there is nothing left to delete. When it raises, or the app's event loop stops
before it finishes, the SDK logs it and tries that organization again on a
later check, at least 5 minutes later. Stackure keeps each one waiting for
1 year.

Until :func:`on_org_closed` is registered, the SDK logs once that closed
organizations are waiting, and the app's page in Stackure shows how many.
Only the app secret receives closed organizations; the development secret
never does.

Configuration
-------------

The SDK reads ``STACKURE_APP_ID``, ``STACKURE_APP_SECRET`` and
``STACKURE_BASE_URL`` once, on its first call, and keeps them until the process
exits. Restart the app after changing them.

``STACKURE_APP_ID`` must be set to the app's UUID, shown on the app page in
Stackure, and ``STACKURE_APP_SECRET`` to the app secret shown when the app was
registered (or last rotated). The secret is sent as the ``X-App-Secret`` header
on every call; every call that needs either raises a ``"validation"``
:class:`StackureError` when it is missing or, for the app ID, not a UUID.
Sign-out needs neither: it sends the secret only when it is set.
``STACKURE_BASE_URL`` must be set to your region's address,
``https://eu.stackure.com`` or ``https://us.stackure.com``. Every call goes
there, and every call raises a ``"validation"`` :class:`StackureError` when it
is unset, isn't an ``https`` URL or has a query or fragment. ``http`` is
accepted only on ``localhost`` or ``127.0.0.1``. A trailing ``/`` is dropped.

People can open a newly registered app once an app admin gives it to everyone
in the organization or to one of their teams in Stackure. App admins and the
owner can always open it, so they can test sign-in first.

Every call has one 2-second deadline covering connect, headers, body and any
retry. Only reads are retried: a session check or directory call is tried once
more after 500 ms on a 5xx or a connection failure, never on a timeout. Calls
that change something are never retried: sending a magic link, the localhost
sign-in code swap, sign-out and the closed organizations check. A timeout
anywhere, including while reading the body, surfaces as ``"timeout"``.

Errors
------

Every function except :func:`verify`, :func:`logout` and
:func:`on_org_closed` raises :class:`StackureError`; those three never raise.
Inspect ``code`` to branch on category: ``"validation"``, ``"auth"``,
``"forbidden"``, ``"timeout"``, ``"network"``.

Releases
--------

Releases are cut from main automatically and versioned ``v1.YYYYMMDD.N``. Each
one carries a GitHub build-provenance attestation and publishes to PyPI via
OIDC trusted publishing.
"""

from .client import send_magic_link
from .errors import StackureError, StackureErrorCode
from .events import on_org_closed
from .middleware import (
    auth,
    directory_teams,
    directory_users,
    logout,
    mcp,
    to_request,
    user_from_request,
    validate_session,
    verify,
)
from .types import (
    DirectoryPage,
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
    "directory_users",
    "directory_teams",
    "on_org_closed",
    "to_request",
    "Request",
    "User",
    "Session",
    "Team",
    "DirectoryPage",
    "DirectoryUser",
    "VerifyError",
    "VerifyResult",
    "MagicLinkResponse",
    "Redirect",
    "StackureError",
    "StackureErrorCode",
]
