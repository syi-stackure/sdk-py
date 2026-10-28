"""Session verification and the ASGI/WSGI authentication middleware."""

import asyncio
import base64
import functools
import hashlib
import io
import json
import logging
import re
import secrets
import urllib.parse
from collections.abc import Callable, Sequence
from http import HTTPStatus
from inspect import iscoroutinefunction
from typing import Any

from .client import (
    APP_COOKIE,
    CODE_COOKIE,
    CODE_PARAM,
    TOKEN_PARAM,
    VERIFIER_COOKIE,
    base_url,
    cookie,
    exchange_code,
    fetch_directory_teams,
    fetch_directory_users,
    session_token,
    sign_out,
    validate_mcp,
    validate_token,
    origin,
)
from .types import (
    DirectoryPage,
    DirectoryUser,
    Redirect,
    Request,
    Team,
    User,
    VerifyError,
    VerifyResult,
)

_logger = logging.getLogger(__name__)
_USER_KEY = "stackure.user"
_MAX_HANDOFF_BODY = 4096
_SESSION_MAX_AGE = 604800
_CODE_MAX_AGE = 60
_VERIFIER_MAX_AGE = 900
_CODE_RE = re.compile(r"^[0-9a-f]{64}$")

type _Reply = tuple[int, list[tuple[str, str]], bytes]


def _from_wsgi(environ: dict[str, Any]) -> Request:
    headers = {
        key[5:].lower().replace("_", "-"): value
        for key, value in environ.items()
        if key.startswith("HTTP_") and isinstance(value, str)
    }
    for key, name in (("CONTENT_TYPE", "content-type"), ("CONTENT_LENGTH", "content-length")):
        if environ.get(key):
            headers[name] = environ[key]
    return Request(
        method=(environ.get("REQUEST_METHOD") or "GET").upper(),
        path=((environ.get("SCRIPT_NAME", "") + environ.get("PATH_INFO", "")) or "/")
        .encode("latin-1", "replace")
        .decode("utf-8", "replace"),
        query=environ.get("QUERY_STRING", ""),
        headers=headers,
        remote_addr=environ.get("REMOTE_ADDR", ""),
        scheme=environ.get("wsgi.url_scheme", "http"),
    )


def _from_asgi(scope: dict[str, Any]) -> Request:
    headers: dict[str, str] = {}
    for key, value in scope.get("headers") or []:
        name, text = key.decode("latin-1").lower(), value.decode("latin-1")
        if name in headers:
            text = headers[name] + ("; " if name == "cookie" else ",") + text
        headers[name] = text
    client = scope.get("client") or ("", 0)
    return Request(
        method=(scope.get("method") or "GET").upper(),
        path=scope.get("path") or "/",
        query=(scope.get("query_string") or b"").decode("latin-1"),
        headers=headers,
        remote_addr=client[0] or "",
        scheme=scope.get("scheme") or "http",
    )


def to_request(source: Any) -> Request:
    """Normalize a WSGI ``environ``, an ASGI ``scope`` or a framework request.

    Accepts anything exposing ``.scope`` (Starlette, FastAPI), ``.environ``
    (Flask, Werkzeug) or ``.META`` (Django).
    """
    if isinstance(source, Request):
        return source
    if not isinstance(source, dict):
        for attr in ("scope", "environ", "META"):
            found = getattr(source, attr, None)
            if isinstance(found, dict):
                source = found
                break
    if isinstance(source, dict):
        if "REQUEST_METHOD" in source:
            return _from_wsgi(source)
        if "type" in source or "headers" in source:
            return _from_asgi(source)
    raise TypeError(f"cannot read an HTTP request from {type(source).__name__}")


def _is_https(request: Request) -> bool:
    return (
        request.scheme == "https"
        or request.headers.get("x-forwarded-proto", "").lower() == "https"
    )


def _is_loopback(request: Request) -> bool:
    host = re.sub(r":[0-9]+$", "", request.headers.get("host", "").lower())
    return host in ("localhost", "127.0.0.1")


def verify(request: Any) -> VerifyResult:
    """Verify a request without raising.

    Callers inspect ``authenticated`` and decide how to respond. Transport and
    API failures come back as a 500 result.

    Args:
        request: A WSGI ``environ``, ASGI ``scope`` or framework request.

    Example:
        >>> result = verify(request)
        >>> if not result.authenticated:
        ...     return result.error.message, result.error.code
    """
    return _check(request)


def _check(request: Any, dev: dict[str, str] | None = None) -> VerifyResult:
    try:
        normalised = to_request(request)
        session = validate_token(session_token(normalised), normalised, dev)
    except Exception as exc:
        _logger.error("stackure: verification error: %s", exc)
        return VerifyResult(error=VerifyError(500, "Authentication verification failed"))

    user = session.user
    if not session.authenticated or user is None:
        return VerifyResult(
            error=VerifyError(401, "Valid authentication required", session.sign_in_url)
        )

    return VerifyResult(authenticated=True, user=user)


def directory_users(
    request: Any,
    *,
    query: str = "",
    cursor: str = "",
    limit: int | None = None,
    ids: Sequence[str] = (),
) -> DirectoryPage[DirectoryUser]:
    """List the users in the caller's Stackure organization who can open the app.

    For pickers and sharing. Returns one page, sorted by first name, then last
    name. Authenticated by the request's session cookie, so call it from a
    route behind :func:`auth`; MCP bearer tokens are not accepted. Synchronous,
    like :func:`verify`.

    Args:
        request: A WSGI ``environ``, ASGI ``scope`` or framework request.
        query: Search text, matching name, email and job title.
        cursor: ``next_cursor`` from the previous page.
        limit: Page size: 100 by default, 200 at most.
        ids: Only these IDs that can open the app, up to 200, to check or
            name people you already store.

    Raises:
        StackureError: ``"auth"`` when there is no valid session, or any
            other transport or API failure.

    Example:
        >>> page = directory_users(request, query="ada")
        >>> emails = [u.user_email for u in page.items]
        >>> if page.next_cursor:
        ...     page = directory_users(request, query="ada", cursor=page.next_cursor)
    """
    return fetch_directory_users(to_request(request), query, cursor, limit, ids)


def directory_teams(
    request: Any,
    *,
    query: str = "",
    cursor: str = "",
    limit: int | None = None,
    ids: Sequence[str] = (),
) -> DirectoryPage[Team]:
    """List the teams in the caller's Stackure organization that have the app.

    Every team when the app is available to everyone, otherwise the teams it's
    shared with. Returns one page, sorted by name. Authenticated and called
    like :func:`directory_users`; ``query`` matches the team name.

    Raises:
        StackureError: ``"auth"`` when there is no valid session, or any
            other transport or API failure.

    Example:
        >>> names = [t.team_name for t in directory_teams(request, limit=50).items]
    """
    return fetch_directory_teams(to_request(request), query, cursor, limit, ids)


def user_from_request(source: Any) -> User | None:
    """The user attached by :func:`auth`, or ``None`` if not authenticated."""
    if not isinstance(source, dict):
        for attr in ("scope", "environ", "META"):
            found = getattr(source, attr, None)
            if isinstance(found, dict):
                source = found
                break
    return source.get(_USER_KEY) if isinstance(source, dict) else None


def _cookie_header(
    name: str, value: str, secure: bool, max_age: int | None = None
) -> tuple[str, str]:
    parts = [f"{name}={value}", "Path=/", "HttpOnly", "SameSite=Lax"]
    if secure:
        parts.append("Secure")
    if max_age is not None:
        parts.append(f"Max-Age={max_age}")
    return ("Set-Cookie", "; ".join(parts))


def _self_url(request: Request) -> str:
    path = request.path
    if not path.startswith("/") or path.startswith(("//", "/\\")):
        return "/"
    path = urllib.parse.quote(path, safe="/:@!$&'()*+,;=")
    return path + (f"?{request.query}" if request.query else "")


def _wants_form(request: Request, origins: tuple[str, ...]) -> bool:
    return (
        request.method == "POST"
        and request.headers.get("origin", "") in origins
        and request.headers.get("content-type", "").startswith(
            "application/x-www-form-urlencoded"
        )
    )


def _same_origin_post(request: Request) -> bool:
    if request.method != "POST":
        return False
    site, sent, host = (request.headers.get(k) for k in ("sec-fetch-site", "origin", "host"))
    if any(v and "," in v for v in (site, sent, host)):
        return False
    if site is not None:
        return site == "same-origin"
    if not sent or not host:
        return False
    scheme, _, authority = sent.lower().partition("://")
    return authority == host.lower() and (scheme == "https" or not _is_https(request))


def _form_origins(request: Request) -> tuple[str, ...]:
    return ("null", origin()) if _is_loopback(request) else (origin(),)


def _form(raw: bytes) -> dict[str, str]:
    parsed = urllib.parse.parse_qs(raw.decode("utf-8", "replace"))
    return {key: values[0] for key, values in parsed.items()}


def _adoptable(token: str, request: Request) -> bool:
    try:
        return validate_token(token, request).authenticated
    except Exception:
        return False


def _error_body(error: VerifyError) -> bytes:
    label = "Unauthorized" if error.code == 401 else "Error"
    return json.dumps(
        {"error": label, "message": error.message, "sign_in_url": error.sign_in_url}
    ).encode()


def _accepts_html(request: Request) -> bool:
    accept = request.headers.get("accept", "")
    return "text/html" in accept and "application/json" not in accept


class _Chain(io.RawIOBase):
    def __init__(self, head: bytes, tail: Any) -> None:
        self.head, self.tail = io.BytesIO(head), tail

    def readable(self) -> bool:
        return True

    def readinto(self, b: Any) -> int:
        n = self.head.readinto(b)
        if n:
            return n
        d = self.tail.read(len(b))
        b[: len(d)] = d
        return len(d)


def _handoff_wsgi(environ: dict[str, Any], request: Request) -> dict[str, str]:
    if not _wants_form(request, _form_origins(request)):
        return {}
    stream = environ["wsgi.input"]
    if environ.get("CONTENT_LENGTH") is None:
        raw = stream.read(_MAX_HANDOFF_BODY + 1)
        if len(raw) > _MAX_HANDOFF_BODY:
            environ["wsgi.input"] = io.BufferedReader(_Chain(raw, stream))
            return {}
        environ["wsgi.input"] = io.BytesIO(raw)
        return _form(raw)
    try:
        length = int(environ["CONTENT_LENGTH"] or 0)
    except ValueError:
        return {}
    if length > _MAX_HANDOFF_BODY:
        return {}
    raw = stream.read(length) if length > 0 else b""
    environ["wsgi.input"] = io.BytesIO(raw)
    return _form(raw)


async def _handoff_asgi(
    receive: Callable[[], Any], request: Request
) -> tuple[dict[str, str], Callable[[], Any]]:
    if not _wants_form(request, _form_origins(request)):
        return {}, receive

    seen: list[dict[str, Any]] = []
    size = 0
    over = False
    while True:
        message = await receive()
        seen.append(message)
        if message["type"] != "http.request":
            break
        size += len(message.get("body", b""))
        over = size > _MAX_HANDOFF_BODY
        if over or not message.get("more_body"):
            break
    raw = b"".join(m.get("body", b"") for m in seen if m["type"] == "http.request")

    async def replay() -> dict[str, Any]:
        return seen.pop(0) if seen else await receive()

    return {} if over else _form(raw), replay


def _adopt(request: Request, form: dict[str, str]) -> _Reply | None:
    token = form.get(TOKEN_PARAM, "") if _wants_form(request, (origin(),)) else ""
    if not token or not _adoptable(token, request):
        return None
    session = _cookie_header(APP_COOKIE, token, _is_https(request), _SESSION_MAX_AGE)
    return 303, [("Location", _self_url(request)), session], b""


def _dev_sign_in(request: Request, verifier: str) -> dict[str, str]:
    scheme = "https" if _is_https(request) else "http"
    digest = hashlib.sha256(verifier.encode()).digest()
    return {
        "return": f"{scheme}://{request.headers.get('host', '')}{_self_url(request)}",
        "challenge": base64.urlsafe_b64encode(digest).rstrip(b"=").decode(),
    }


def _stash(request: Request, form: dict[str, str]) -> _Reply | None:
    code = form.get(CODE_PARAM, "") if _wants_form(request, ("null", origin())) else ""
    if not _CODE_RE.fullmatch(code):
        return None
    stash = _cookie_header(CODE_COOKIE, code, _is_https(request), _CODE_MAX_AGE)
    return 303, [("Location", _self_url(request)), stash], b""


def _redeem(request: Request) -> _Reply | None:
    code = cookie(request, CODE_COOKIE)
    if not code:
        return None
    secure = _is_https(request)
    clear = [_cookie_header(name, "", secure, 0) for name in (CODE_COOKIE, VERIFIER_COOKIE)]

    try:
        token = exchange_code(code, cookie(request, VERIFIER_COOKIE), request)
    except Exception as exc:
        _logger.error("stackure: localhost sign-in failed: %s", exc)
        return (
            401,
            [*clear, ("Content-Type", "application/json")],
            b'{"error":"localhost sign-in failed, reload to try again"}',
        )

    session = _cookie_header(APP_COOKIE, token, secure, _SESSION_MAX_AGE)
    return 303, [("Location", _self_url(request)), *clear, session], b""


def _auth_verify(request: Request, form: dict[str, str]) -> User | None | _Reply:
    local = _is_loopback(request)
    reply = _adopt(request, form)
    if local and not reply:
        reply = _stash(request, form) or _redeem(request)
    if reply:
        return reply

    verifier = secrets.token_urlsafe(32) if local else ""
    result = _check(request, _dev_sign_in(request, verifier) if local else None)
    error = result.error
    if not result.authenticated and error:
        if error.code == 401 and _accepts_html(request) and error.sign_in_url:
            headers = [("Location", error.sign_in_url)]
            if local:
                secure = _is_https(request)
                headers.append(
                    _cookie_header(VERIFIER_COOKIE, verifier, secure, _VERIFIER_MAX_AGE)
                )
            return 302, headers, b""
        return error.code, [("Content-Type", "application/json")], _error_body(error)

    return result.user


def _send_wsgi(
    start_response: Callable[..., Any],
    status: int,
    headers: list[tuple[str, str]],
    body: bytes = b"",
) -> list[bytes]:
    start_response(
        f"{status} {HTTPStatus(status).phrase}",
        [*headers, ("Content-Length", str(len(body)))],
    )
    return [body]


async def _send_asgi(
    send: Callable[[dict[str, Any]], Any],
    status: int,
    headers: list[tuple[str, str]],
    body: bytes = b"",
) -> None:
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": [
                (key.lower().encode("latin-1"), value.encode("latin-1"))
                for key, value in [*headers, ("content-length", str(len(body)))]
            ],
        }
    )
    await send({"type": "http.response.body", "body": body})


def _is_asgi(app: Any) -> bool:
    while isinstance(app, functools.partial):
        app = app.func
    return iscoroutinefunction(app) or (
        callable(app) and iscoroutinefunction(app.__call__)
    )


def auth() -> Callable[[Any], Any]:
    """Middleware that enforces authentication, for ASGI or WSGI apps.

    Completes Stackure's sign-in handoff by validating the POSTed
    ``session_token`` and storing it as a cookie on your domain. On success the user is attached to the request (read it back with
    :func:`user_from_request`). Browser requests get redirected to sign-in on
    401; API requests get JSON.

    On localhost or 127.0.0.1 with the app's development secret, sign-in
    returns to the page that asked for it: Stackure posts a one-time code
    there, and the middleware swaps it for a session using the secret and a
    check value it keeps in a cookie. Only app admins of the organization that
    added the app can sign in this way.

    The app you wrap decides the protocol: an awaitable callable yields ASGI
    middleware, anything else yields WSGI middleware.

    Example:
        >>> app = auth()(app)  # ASGI
        >>> flask_app.wsgi_app = auth()(flask_app.wsgi_app)
    """

    def factory(app: Any) -> Any:
        if _is_asgi(app):

            async def asgi(scope: dict[str, Any], receive: Any, send: Any) -> Any:
                if scope.get("type") != "http":
                    return await app(scope, receive, send)

                request = _from_asgi(scope)
                form, receive = await _handoff_asgi(receive, request)
                result = await asyncio.to_thread(_auth_verify, request, form)
                if isinstance(result, tuple):
                    return await _send_asgi(send, *result)

                scope[_USER_KEY] = result
                return await app(scope, receive, send)

            return asgi

        def wsgi(environ: dict[str, Any], start_response: Any) -> Any:
            request = _from_wsgi(environ)
            result = _auth_verify(request, _handoff_wsgi(environ, request))
            if isinstance(result, tuple):
                return _send_wsgi(start_response, *result)

            environ[_USER_KEY] = result
            return app(environ, start_response)

        return wsgi

    return factory


def _mcp_url(request: Request) -> str:
    scheme = "https" if _is_https(request) else "http"
    path = urllib.parse.quote(request.path, safe="/:@!$&'()*+,;=")
    return f"{scheme}://{request.headers.get('host', '')}{path}"


def _bearer(request: Request) -> str:
    scheme, _, token = request.headers.get("authorization", "").partition(" ")
    return token.strip() if scheme.lower() == "bearer" else ""


def _mcp_verify(request: Request) -> User | tuple[int, list[tuple[str, str]], bytes]:
    json_type = ("Content-Type", "application/json")
    try:
        user, challenge = validate_mcp(_mcp_url(request), _bearer(request), request)
    except Exception as exc:
        _logger.error(
            "stackure: mcp verification failed: %s", getattr(exc, "code", type(exc).__name__)
        )
        return 503, [json_type], b'{"error":"unavailable"}'

    if user is None:
        return 401, [("WWW-Authenticate", challenge), json_type], b'{"error":"unauthorized"}'

    return user


def mcp() -> Callable[[Any], Any]:
    """Middleware that enforces authentication on an MCP endpoint, for ASGI or WSGI apps.

    AI clients sign users in through Stackure and send the credential it
    issues as ``Authorization: Bearer``. Every MCP request is checked against
    Stackure in real time with the same app secret as :func:`auth`; cookies
    are ignored. On success the user is attached to the request (read it back
    with :func:`user_from_request`).

    Never redirects and never touches cookies. A request that is not signed in
    gets a 401 with the ``WWW-Authenticate`` header AI clients follow to sign
    in and a failed check a 503, each as JSON.

    The MCP endpoint must be served from the same site as the app's registered
    URL unless an MCP URL is set for the app in Stackure.

    Example:
        >>> app.mount("/mcp", mcp()(mcp_app))  # ASGI
        >>> mcp_wsgi_app = mcp()(mcp_wsgi_app)
    """

    def factory(app: Any) -> Any:
        if _is_asgi(app):

            async def asgi(scope: dict[str, Any], receive: Any, send: Any) -> Any:
                if scope.get("type") != "http":
                    return await app(scope, receive, send)

                result = await asyncio.to_thread(_mcp_verify, _from_asgi(scope))
                if not isinstance(result, User):
                    return await _send_asgi(send, *result)

                scope[_USER_KEY] = result
                return await app(scope, receive, send)

            return asgi

        def wsgi(environ: dict[str, Any], start_response: Any) -> Any:
            result = _mcp_verify(_from_wsgi(environ))
            if not isinstance(result, User):
                return _send_wsgi(start_response, *result)

            environ[_USER_KEY] = result
            return app(environ, start_response)

        return wsgi

    return factory


def logout(request: Any) -> Redirect:
    """Sign the user out of Stackure everywhere and clear the app's session cookie.

    Mount it for every method on the sign-out path. Trigger it with a form or
    button that POSTs from the app's own page; a link or any other request is
    sent to Stackure's sign-out page, where the user confirms.

    A same-origin POST makes one server-side call to Stackure with the app
    session token, clears the cookie and redirects to Stackure. If that call
    fails, the redirect goes to Stackure's sign-out page instead, where the
    user can finish signing out.

    Synchronous and never raises. Returns a :class:`Redirect`, the status and
    headers to send; your framework builds the response.

    Example:
        >>> methods = ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]
        >>> @flask_app.route("/logout", methods=methods)
        ... def sign_out():
        ...     r = logout(flask.request.environ)
        ...     return "", r.status, r.headers
    """
    path = "/signout"
    clear: list[tuple[str, str]] = []
    try:
        normalised = to_request(request)
        if _same_origin_post(normalised):
            clear = [_cookie_header(APP_COOKIE, "", _is_https(normalised), 0)]
            sign_out(session_token(normalised), normalised)
            path = "/"
    except Exception as exc:
        _logger.error("stackure: sign-out failed: %s", getattr(exc, "code", type(exc).__name__))
    return Redirect(303, [("Location", base_url() + path), *clear])
