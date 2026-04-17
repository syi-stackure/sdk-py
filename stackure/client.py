"""Internal HTTP layer for the Stackure SDK.

Consumers should use the module-level ``send_magic_link`` and ``logout``
functions re-exported from ``stackure``; they go through this layer.
"""

import asyncio
import os

import httpx

from .errors import StackureError
from .types import MagicLinkResponse, User
from .validation import validate_email, validate_uuid

_DEFAULT_BASE_URL = "https://stackure.com"
_REQUEST_TIMEOUT_S = 10.0
_MAX_RETRIES = 2


def _base_url() -> str:
    """Resolve the base URL from ``STACKURE_BASE_URL`` or fall back to production."""
    env = os.environ.get("STACKURE_BASE_URL")
    return env.rstrip("/") if env else _DEFAULT_BASE_URL


async def _request(method: str, path: str, **kwargs) -> httpx.Response:
    """Perform an HTTP request with retry + timeout.

    Retries 5xx responses twice with exponential backoff (500ms, 1s). Timeouts
    are never retried — a second attempt would obscure real latency.
    """
    url = f"{_base_url()}{path}"
    last_error: Exception | None = None

    for attempt in range(_MAX_RETRIES + 1):
        if attempt > 0:
            await asyncio.sleep(0.5 * (2 ** (attempt - 1)))
        try:
            async with httpx.AsyncClient(timeout=_REQUEST_TIMEOUT_S) as http_client:
                response = await http_client.request(method, url, **kwargs)
            if response.status_code >= 500 and attempt < _MAX_RETRIES:
                last_error = StackureError(
                    "network",
                    f"Server error ({response.status_code})",
                    response.status_code,
                )
                continue
            return response
        except httpx.TimeoutException as exc:
            raise StackureError(
                "timeout",
                f"Request timed out after {_REQUEST_TIMEOUT_S}s",
            ) from exc
        except httpx.RequestError as exc:
            last_error = StackureError("network", f"Network request failed: {exc}")

    raise last_error or StackureError("network", "Request failed after retries")


def _handle_response(response: httpx.Response) -> dict:
    """Return parsed JSON or raise a typed :class:`StackureError` for non-2xx."""
    if not response.is_success:
        try:
            error_text = response.text
        except Exception:
            error_text = "unknown error"
        if response.status_code == 401:
            raise StackureError("auth", error_text or "Authentication failed", 401)
        if response.status_code == 403:
            raise StackureError("forbidden", error_text or "Access forbidden", 403)
        raise StackureError(
            "network",
            f"API error ({response.status_code}): {error_text}",
            response.status_code,
        )
    try:
        return response.json()
    except Exception as exc:
        raise StackureError("network", "Invalid JSON response from server") from exc


async def send_magic_link(email: str, app_id: str | None = None) -> MagicLinkResponse:
    """Send a passwordless sign-in email to a user.

    Args:
        email: Recipient's email address.
        app_id: Your Stackure application UUID. Optional.

    Returns:
        :class:`MagicLinkResponse` with the API's confirmation message.

    Raises:
        StackureError: With ``code`` in ``{"validation", "network", "timeout", "auth"}``.
    """
    validate_email(email)
    if app_id:
        validate_uuid(app_id, "App ID")
    body: dict = {"user_email": email}
    if app_id:
        body["app_id"] = app_id
    response = await _request("POST", "/api/public/auth/magic-link/send", json=body)
    data = _handle_response(response)
    try:
        return MagicLinkResponse(message=data["message"])
    except KeyError as exc:
        raise StackureError("network", "Unexpected API response format") from exc


async def _validate_session(app_id: str, cookies: dict | None = None) -> dict:
    """Internal helper: validate a session and return the raw API response dict."""
    validate_uuid(app_id, "App ID")
    response = await _request(
        "GET",
        "/api/public/auth/session/validate",
        params={"app_id": app_id},
        cookies=cookies,
    )
    data = _handle_response(response)
    user = None
    if data.get("user"):
        u = data["user"]
        try:
            user = User(
                user_id=u["user_id"],
                user_email=u["user_email"],
                user_first_name=u["user_first_name"],
                user_last_name=u["user_last_name"],
                user_roles=u.get("user_roles", []),
            )
        except KeyError as exc:
            raise StackureError("network", "Unexpected user payload format") from exc
    return {
        "authenticated": data.get("authenticated", False),
        "user": user,
        "sign_in_url": data.get("sign_in_url"),
    }


async def logout(cookies: dict | None = None) -> None:
    """Revoke the session represented by ``cookies``.

    Args:
        cookies: Cookies from the incoming HTTP request.

    Raises:
        StackureError: With ``code`` in ``{"network", "timeout"}``.
    """
    response = await _request("POST", "/api/public/auth/sign-out", cookies=cookies)
    _handle_response(response)
