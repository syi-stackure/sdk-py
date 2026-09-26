"""HTTP layer for the Stackure SDK. Standard library only."""

import http.client
import io
import json
import os
import socket
import time
import urllib.parse
from typing import Any

from .errors import StackureError
from .types import MagicLinkResponse, Request, Session, User
from .validation import is_uuid, validate_email, validate_uuid

_DEFAULT_BASE_URL = "https://stackure.com"
_REQUEST_TIMEOUT_S = 2.0
_MAX_RETRIES = 1
_RETRY_DELAY_S = 0.5

SESSION_COOKIE = "session"
APP_COOKIE = "stackure_session"
TOKEN_PARAM = "session_token"


def origin() -> str:
    u = urllib.parse.urlsplit(base_url())
    return f"{u.scheme}://{u.netloc}"


def base_url() -> str:
    """Resolve ``STACKURE_BASE_URL`` from the environment, else production."""
    env = os.environ.get("STACKURE_BASE_URL")
    return env.rstrip("/") if env else _DEFAULT_BASE_URL


def app_secret() -> str:
    """Resolve ``STACKURE_APP_SECRET`` from the environment. Required."""
    v = os.environ.get("STACKURE_APP_SECRET")
    if not v:
        raise StackureError("validation", "STACKURE_APP_SECRET is not set")
    return v


def _timeout() -> StackureError:
    return StackureError("timeout", f"request timed out after {_REQUEST_TIMEOUT_S}s")


def _left(deadline: float) -> float:
    left = deadline - time.monotonic()
    if left <= 0:
        raise TimeoutError
    return left


class _Raw(socket.SocketIO):
    def __init__(self, sock: Any, deadline: float) -> None:
        super().__init__(sock, "rb")
        sock._io_refs += 1
        self.deadline = deadline

    def readinto(self, b: Any) -> int | None:
        self._sock.settimeout(_left(self.deadline))
        return super().readinto(b)


def _response(deadline: float) -> type[http.client.HTTPResponse]:
    class R(http.client.HTTPResponse):
        def __init__(self, sock: Any, *a: Any, **kw: Any) -> None:
            super().__init__(sock, *a, **kw)
            self.fp.close()
            self.fp = io.BufferedReader(_Raw(sock, deadline))

    return R


def _can_retry(attempt: int, deadline: float) -> bool:
    return attempt < _MAX_RETRIES and deadline - time.monotonic() > _RETRY_DELAY_S


def _read(resp: Any) -> bytes:
    try:
        return resp.read()
    except TimeoutError as exc:
        raise _timeout() from exc
    except (OSError, http.client.HTTPException):
        raise
    except Exception as exc:
        raise StackureError("network", "failed to read response body", resp.status) from exc


def _handle_response(status: int, raw: bytes) -> Any:
    text = raw.decode("utf-8", "replace")
    if not 200 <= status < 300:
        body = text or "unknown error"
        if status == 401:
            raise StackureError("auth", body, 401)
        if status == 403:
            raise StackureError("forbidden", body, 403)
        raise StackureError("network", f"api error ({status}): {body}", status)
    try:
        return json.loads(text)
    except ValueError as exc:
        raise StackureError("network", "invalid JSON response from server", status) from exc


def _request(
    method: str,
    path: str,
    *,
    body: Any = None,
    query: dict[str, str] | None = None,
    token: str = "",
    ua: str = "",
    ip: str = "",
) -> Any:
    base = urllib.parse.urlsplit(base_url())
    target = base.path + path
    if query:
        target += "?" + urllib.parse.urlencode(query)

    data = json.dumps(body).encode() if body is not None else None
    headers = {"X-App-Secret": app_secret()}
    if data is not None:
        headers["Content-Type"] = "application/json"
    if ua:
        headers["User-Agent"] = ua
    if ip:
        headers["X-Forwarded-For"] = ip
    if token:
        headers["Cookie"] = f"{SESSION_COOKIE}={token}"

    cls = http.client.HTTPSConnection if base.scheme == "https" else http.client.HTTPConnection
    deadline = time.monotonic() + _REQUEST_TIMEOUT_S
    for attempt in range(_MAX_RETRIES + 1):
        if attempt:
            time.sleep(_RETRY_DELAY_S)
        conn = None
        try:
            conn = cls(base.netloc, timeout=_left(deadline))
            conn.response_class = _response(deadline)
            conn.connect()
            conn.sock.settimeout(_left(deadline))
            conn.request(method, target, body=data, headers=headers)
            resp = conn.getresponse()
            status, payload = resp.status, _read(resp)
        except TimeoutError as exc:
            raise _timeout() from exc
        except (OSError, http.client.HTTPException) as exc:
            if not _can_retry(attempt, deadline):
                raise StackureError("network", f"network request failed: {exc}") from exc
            continue
        finally:
            if conn:
                conn.close()
        if status >= 500 and _can_retry(attempt, deadline):
            continue
        return _handle_response(status, payload)


def client_ip(request: Request) -> str:
    """The client's address: first ``X-Forwarded-For`` entry, else the peer."""
    forwarded = request.headers.get("x-forwarded-for", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr


def cookie(request: Request, name: str) -> str:
    """Read a single cookie off ``request``, or ``""`` if absent."""
    for part in request.headers.get("cookie", "").split(";"):
        key, sep, value = part.partition("=")
        if sep and key.strip() == name:
            value = value.strip()
            if len(value) >= 2 and value[0] == value[-1] == '"':
                value = value[1:-1]
            return value
    return ""


def session_token(request: Request) -> str:
    """The session token from the app's session cookie."""
    return cookie(request, APP_COOKIE)


def _user(data: Any) -> User | None:
    if not data:
        return None
    try:
        return User(
            user_id=data["user_id"],
            user_email=data["user_email"],
            user_first_name=data["user_first_name"],
            user_last_name=data["user_last_name"],
            user_permissions=data.get("user_permissions") or [],
        )
    except (KeyError, TypeError) as exc:
        raise StackureError("network", "unexpected user payload format") from exc


def send_magic_link(email: str, app_id: str | None = None) -> MagicLinkResponse:
    """Send a passwordless sign-in email.

    Args:
        email: Recipient's email address.
        app_id: Your Stackure application UUID. Optional.

    Returns:
        The API's confirmation message.

    Raises:
        StackureError: ``code`` is one of ``"validation"``, ``"auth"``,
            ``"forbidden"``, ``"timeout"``, ``"network"``.

    Example:
        >>> send_magic_link("user@example.com", app_id).message
        'Magic link sent'
    """
    validate_email(email)

    body: dict[str, str] = {"user_email": email}
    if app_id:
        validate_uuid(app_id, "App ID")
        body["app_id"] = app_id

    data = _request("POST", "/api/public/auth/magic-link/send", body=body)
    try:
        return MagicLinkResponse(message=data["message"])
    except (KeyError, TypeError) as exc:
        raise StackureError("network", "unexpected API response format") from exc


def validate_session(app_id: str, request: Request) -> Session:
    """Validate ``request``'s session against Stackure.

    A request without a well-formed session token gets the sign-in URL
    without a Stackure call.

    Most callers want :func:`~stackure.verify` or :func:`~stackure.auth`.

    Raises:
        StackureError: On invalid input, or any transport or API failure.
    """
    return validate_token(app_id, session_token(request), request)


def validate_token(app_id: str, token: str, request: Request) -> Session:
    """Validate an explicit session ``token`` for ``request``'s browser."""
    validate_uuid(app_id, "App ID")

    if not is_uuid(token):
        return Session(
            authenticated=False,
            sign_in_url=f"{base_url()}/sign-in/magic-link?app_id={app_id}",
        )

    data = _request(
        "GET",
        "/api/public/auth/session/validate",
        query={"app_id": app_id},
        token=token,
        ua=request.headers.get("user-agent", ""),
        ip=client_ip(request),
    )
    return Session(
        authenticated=bool(data.get("authenticated")),
        user=_user(data.get("user")),
        sign_in_url=data.get("sign_in_url") or "",
    )
