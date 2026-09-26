"""Session verification and the ASGI/WSGI authentication middleware."""

import asyncio
import functools
import io
import json
import logging
import urllib.parse
from collections.abc import Callable
from http import HTTPStatus
from inspect import iscoroutinefunction
from typing import Any

from .client import (
    APP_COOKIE,
    TOKEN_PARAM,
    base_url,
    cookie,
    validate_session,
    validate_token,
    origin,
)
from .types import Redirect, Request, User, VerifyError, VerifyResult

_logger = logging.getLogger(__name__)
_USER_KEY = "stackure.user"
_MAX_HANDOFF_BODY = 4096
_SESSION_MAX_AGE = 604800


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
    headers = {
        key.decode("latin-1").lower(): value.decode("latin-1")
        for key, value in scope.get("headers") or []
    }
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
    """Normalise a WSGI ``environ``, an ASGI ``scope``, or a framework request.

    Accepts anything exposing ``.scope`` (Starlette, FastAPI), ``.environ``
    (Flask, Werkzeug), or ``.META`` (Django).
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


def verify(app_id: str, request: Any, *permissions: str) -> VerifyResult:
    """Verify a request without raising.

    Callers inspect ``authenticated`` and decide how to respond. Transport and
    API failures come back as a 500 result.

    Args:
        app_id: Your Stackure application UUID.
        request: A WSGI ``environ``, ASGI ``scope``, or framework request.
        *permissions: Optional required permissions; the user must hold one.

    Example:
        >>> result = verify(app_id, request, "can_approve_invoice")
        >>> if not result.authenticated:
        ...     return result.error.message, result.error.code
    """
    try:
        session = validate_session(app_id, to_request(request))
    except Exception as exc:
        _logger.error("stackure: verification error: %s", exc)
        return VerifyResult(error=VerifyError(500, "Authentication verification failed"))

    user = session.user
    if not session.authenticated or user is None:
        return VerifyResult(
            error=VerifyError(401, "Valid authentication required", session.sign_in_url)
        )

    if permissions and not any(p in user.user_permissions for p in permissions):
        return VerifyResult(
            user=user,
            error=VerifyError(403, f"Requires one of: {', '.join(permissions)}"),
        )

    return VerifyResult(authenticated=True, user=user)


def user_from_request(source: Any) -> User | None:
    """The user attached by :func:`auth`, or ``None`` if not authenticated."""
    if not isinstance(source, dict):
        for attr in ("scope", "environ", "META"):
            found = getattr(source, attr, None)
            if isinstance(found, dict):
                source = found
                break
    return source.get(_USER_KEY) if isinstance(source, dict) else None


def _cookie_header(value: str, secure: bool, max_age: int | None = None) -> tuple[str, str]:
    parts = [f"{APP_COOKIE}={value}", "Path=/", "HttpOnly", "SameSite=Lax"]
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


def _wants_form_token(request: Request) -> bool:
    return (
        request.method == "POST"
        and request.headers.get("origin", "") == origin()
        and request.headers.get("content-type", "").startswith(
            "application/x-www-form-urlencoded"
        )
    )


def _form_token(raw: bytes) -> str:
    parsed = urllib.parse.parse_qs(raw.decode("utf-8", "replace"))
    return parsed.get(TOKEN_PARAM, [""])[0]


def _adoptable(app_id: str, token: str, request: Request) -> bool:
    try:
        return validate_token(app_id, token, request).authenticated
    except Exception:
        return False


def _error_body(error: VerifyError) -> bytes:
    label = {401: "Unauthorized", 403: "Forbidden"}.get(error.code, "Error")
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


def _handoff_wsgi(environ: dict[str, Any], request: Request) -> str:
    if not _wants_form_token(request):
        return ""
    stream = environ["wsgi.input"]
    if environ.get("CONTENT_LENGTH") is None:
        raw = stream.read(_MAX_HANDOFF_BODY + 1)
        if len(raw) > _MAX_HANDOFF_BODY:
            environ["wsgi.input"] = io.BufferedReader(_Chain(raw, stream))
            return ""
        environ["wsgi.input"] = io.BytesIO(raw)
        return _form_token(raw)
    try:
        length = int(environ["CONTENT_LENGTH"] or 0)
    except ValueError:
        return ""
    if length > _MAX_HANDOFF_BODY:
        return ""
    raw = stream.read(length) if length > 0 else b""
    environ["wsgi.input"] = io.BytesIO(raw)
    return _form_token(raw)


async def _handoff_asgi(
    receive: Callable[[], Any], request: Request
) -> tuple[str, Callable[[], Any]]:
    if not _wants_form_token(request):
        return "", receive

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

    return "" if over else _form_token(raw), replay


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


def auth(app_id: str, *permissions: str) -> Callable[[Any], Any]:
    """Middleware that enforces authentication, for ASGI or WSGI apps.

    Completes Stackure's sign-in handoff by validating the POSTed
    ``session_token`` and storing it as a cookie on your domain. On success the user is attached to the request (read it back with
    :func:`user_from_request`). Browser requests get redirected to sign-in on
    401; API requests get JSON.

    The app you wrap decides the protocol: an awaitable callable yields ASGI
    middleware, anything else yields WSGI middleware.

    Example:
        >>> app = auth(app_id, "can_approve_invoice")(app)          # ASGI
        >>> flask_app.wsgi_app = auth(app_id)(flask_app.wsgi_app)
    """

    def factory(app: Any) -> Any:
        if _is_asgi(app):

            async def asgi(scope: dict[str, Any], receive: Any, send: Any) -> Any:
                if scope.get("type") != "http":
                    return await app(scope, receive, send)

                request = _from_asgi(scope)
                token, receive = await _handoff_asgi(receive, request)
                if token and await asyncio.to_thread(_adoptable, app_id, token, request):
                    return await _send_asgi(
                        send,
                        303,
                        [
                            ("location", _self_url(request)),
                            _cookie_header(token, _is_https(request), _SESSION_MAX_AGE),
                        ],
                    )

                result = await asyncio.to_thread(verify, app_id, request, *permissions)
                error = result.error
                if not result.authenticated and error:
                    if error.code == 401 and _accepts_html(request) and error.sign_in_url:
                        return await _send_asgi(send, 302, [("location", error.sign_in_url)])
                    return await _send_asgi(
                        send,
                        error.code,
                        [("content-type", "application/json")],
                        _error_body(error),
                    )

                scope[_USER_KEY] = result.user
                return await app(scope, receive, send)

            return asgi

        def wsgi(environ: dict[str, Any], start_response: Any) -> Any:
            request = _from_wsgi(environ)
            token = _handoff_wsgi(environ, request)
            if token and _adoptable(app_id, token, request):
                return _send_wsgi(
                    start_response,
                    303,
                    [
                        ("Location", _self_url(request)),
                        _cookie_header(token, _is_https(request), _SESSION_MAX_AGE),
                    ],
                )

            result = verify(app_id, request, *permissions)
            error = result.error
            if not result.authenticated and error:
                if error.code == 401 and _accepts_html(request) and error.sign_in_url:
                    return _send_wsgi(start_response, 302, [("Location", error.sign_in_url)])
                return _send_wsgi(
                    start_response,
                    error.code,
                    [("Content-Type", "application/json")],
                    _error_body(error),
                )

            environ[_USER_KEY] = result.user
            return app(environ, start_response)

        return wsgi

    return factory


def logout(request: Any) -> Redirect:
    """Clear the app's session cookie and redirect to Stackure's sign-out.

    Returns the status and headers to send; your framework builds the
    response.

    Example:
        >>> r = logout(flask.request.environ)
        >>> return "", r.status, r.headers
    """
    normalised = to_request(request)
    return Redirect(
        303,
        [
            ("Location", base_url() + "/signout"),
            _cookie_header("", _is_https(normalised), 0),
        ],
    )
