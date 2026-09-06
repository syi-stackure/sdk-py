"""HTTP layer for the Stackure SDK. Standard library only."""

import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from .errors import StackureError
from .types import MagicLinkResponse, Request, Session, User
from .validation import validate_email, validate_uuid

_DEFAULT_BASE_URL = "https://stackure.com"
_REQUEST_TIMEOUT_S = 2.0
_MAX_RETRIES = 1
_RETRY_DELAY_S = 0.5

SESSION_COOKIE = "session"
TOKEN_PARAM = "session_token"


def base_url() -> str:
    """Resolve ``STACKURE_BASE_URL`` from the environment, else production."""
    env = os.environ.get("STACKURE_BASE_URL")
    return env.rstrip("/") if env else _DEFAULT_BASE_URL


def _read(resp: Any, status: int) -> bytes:
    try:
        return resp.read()
    except Exception as exc:
        raise StackureError("network", "failed to read response body", status) from exc


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
    url = base_url() + path
    if query:
        url += "?" + urllib.parse.urlencode(query)

    data = json.dumps(body).encode() if body is not None else None
    headers = {}
    if data is not None:
        headers["Content-Type"] = "application/json"
    if ua:
        headers["User-Agent"] = ua
    if ip:
        headers["X-Forwarded-For"] = ip
    if token:
        headers["Cookie"] = f"{SESSION_COOKIE}={token}"

    last: StackureError | None = None
    for attempt in range(_MAX_RETRIES + 1):
        if attempt:
            time.sleep(_RETRY_DELAY_S)
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=_REQUEST_TIMEOUT_S) as resp:
                status, payload = resp.status, _read(resp, resp.status)
            return _handle_response(status, payload)
        except urllib.error.HTTPError as exc:
            payload = _read(exc, exc.code)
            if exc.code >= 500 and attempt < _MAX_RETRIES:
                last = StackureError("network", f"server error ({exc.code})", exc.code)
                continue
            return _handle_response(exc.code, payload)
        except TimeoutError as exc:
            raise StackureError(
                "timeout", f"request timed out after {_REQUEST_TIMEOUT_S}s"
            ) from exc
        except urllib.error.URLError as exc:
            if isinstance(exc.reason, TimeoutError):
                raise StackureError(
                    "timeout", f"request timed out after {_REQUEST_TIMEOUT_S}s"
                ) from exc
            last = StackureError("network", f"network request failed: {exc.reason}")

    raise last or StackureError("network", "request failed after retries")


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
            return value.strip()
    return ""


def query_param(request: Request, name: str) -> str:
    """Read a single query-string parameter, or ``""`` if absent."""
    return urllib.parse.parse_qs(request.query).get(name, [""])[0]


def session_token(request: Request) -> str:
    """The session token: handoff query parameter first, then the cookie."""
    return query_param(request, TOKEN_PARAM) or cookie(request, SESSION_COOKIE)


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

    Most callers want :func:`~stackure.verify` or :func:`~stackure.auth`.

    Raises:
        StackureError: On invalid input, or any transport or API failure.
    """
    validate_uuid(app_id, "App ID")

    data = _request(
        "GET",
        "/api/public/auth/session/validate",
        query={"app_id": app_id},
        token=session_token(request),
        ua=request.headers.get("user-agent", ""),
        ip=client_ip(request),
    )
    return Session(
        authenticated=bool(data.get("authenticated")),
        user=_user(data.get("user")),
        sign_in_url=data.get("sign_in_url") or "",
    )
