"""Authentication verification middleware helpers for the Stackure SDK."""

import asyncio
import functools
import inspect
import logging
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from .client import StackureClient
from .errors import AuthenticationError, ForbiddenError
from .types import StackureUser

_logger = logging.getLogger(__name__)
_default_client = StackureClient()


@dataclass
class VerifyResult:
    """Result of an authentication verification check.

    Attributes:
        authenticated: Whether the request carries a valid session.
        user: Authenticated user details. Present only when ``authenticated`` is ``True``.
        error: Error context when ``authenticated`` is ``False``. Contains
            ``code`` (int), ``message`` (str), and optionally ``sign_in_url`` (str).
    """

    authenticated: bool
    user: StackureUser | None = None
    error: dict | None = None


async def verify(
    app_id: str,
    cookies: dict | None = None,
    roles: list[str] | None = None,
    client: StackureClient | None = None,
) -> VerifyResult:
    """Verify authentication for an incoming request.

    Validates the session and optionally enforces role requirements.
    Returns a structured result without raising exceptions, allowing
    callers to decide how to handle unauthenticated or unauthorized requests.

    Args:
        app_id: Your Stackure application UUID.
        cookies: Session cookies from the incoming HTTP request. Pass
            ``dict(request.cookies)`` from your web framework.
        roles: Optional list of acceptable role names. The user must hold
            at least one of these roles to be considered authorized.
        client: Optional :class:`~stackure.StackureClient` instance to use instead
            of the shared default client.

    Returns:
        A :class:`VerifyResult` with ``authenticated=True`` and populated ``user``
        on success, or ``authenticated=False`` with an ``error`` dict on failure.

    Example:
        >>> result = await verify(app_id="your-app-id", cookies=dict(request.cookies))
        >>> if not result.authenticated:
        ...     return {"error": result.error["message"]}, result.error["code"]
        >>> return {"user": result.user}
    """
    if client is None:
        client = _default_client
    try:
        session = await client.validate_session(app_id, cookies)
        if not session.authenticated or not session.user:
            return VerifyResult(
                authenticated=False,
                error={
                    "code": 401,
                    "message": "Valid authentication required",
                    "sign_in_url": session.sign_in_url,
                },
            )
        if roles:
            user_roles = session.user.user_roles or []
            if not any(role in user_roles for role in roles):
                return VerifyResult(
                    authenticated=False,
                    user=session.user,
                    error={"code": 403, "message": f"Requires one of: {', '.join(roles)}"},
                )
        return VerifyResult(authenticated=True, user=session.user)
    except Exception as e:
        _logger.error("Stackure verification error: %s", e)
        return VerifyResult(
            authenticated=False,
            error={"code": 500, "message": "Authentication verification failed"},
        )


def _extract_cookies(request: Any) -> dict:
    """Extract cookies from a framework request object.

    Supports any framework that exposes cookies as a ``cookies`` attribute
    (FastAPI, Starlette, Flask, aiohttp) or a ``COOKIES`` attribute (Django).

    Args:
        request: Framework-specific HTTP request object.

    Returns:
        A plain dict of cookie name/value pairs, or an empty dict.
    """
    if request is None:
        return {}
    cookies = getattr(request, "cookies", None) or getattr(request, "COOKIES", None)
    return dict(cookies) if cookies else {}


def _raise_for_verify_result(result: VerifyResult) -> None:
    """Raise the appropriate exception for a failed VerifyResult.

    Args:
        result: A VerifyResult where ``authenticated`` is ``False``.

    Raises:
        ForbiddenError: When the error code is 403.
        AuthenticationError: For all other failure codes.
    """
    code = result.error["code"] if result.error else 401
    message = result.error["message"] if result.error else "Authentication required"
    if code == 403:
        raise ForbiddenError(message)
    raise AuthenticationError(message)


def auth(
    app_id: str,
    roles: list[str] | None = None,
    client: StackureClient | None = None,
) -> Callable:
    """Decorator that enforces authentication on a view function.

    Validates the session before the decorated function is called. On success,
    sets ``request.user`` to the authenticated :class:`~stackure.StackureUser`.
    On failure, raises :class:`~stackure.AuthenticationError` (401) or
    :class:`~stackure.ForbiddenError` (403).

    Supports both synchronous and asynchronous view functions. Sync views that
    require this decorator must not already be running inside an event loop
    (i.e., they should be plain WSGI views, not ASGI coroutines).

    Args:
        app_id: Your Stackure application UUID.
        roles: Optional list of acceptable role names. The user must hold at
            least one of these roles to be considered authorized.
        client: Optional :class:`~stackure.StackureClient` instance; uses the
            module-level default when omitted.

    Returns:
        A decorator that wraps the target view function.

    Raises:
        AuthenticationError: When the session is absent or invalid.
        ForbiddenError: When the user lacks the required role.

    Example:
        >>> @app.get("/dashboard")
        ... @auth(app_id="your-app-id", roles=["admin"])
        ... async def dashboard(request):
        ...     return {"user": request.user}
    """

    def decorator(func: Callable) -> Callable:
        if inspect.iscoroutinefunction(func):

            @functools.wraps(func)
            async def _async_wrapper(*args: Any, **kwargs: Any) -> Any:
                request = args[0] if args else kwargs.get("request")
                result = await verify(
                    app_id,
                    cookies=_extract_cookies(request),
                    roles=roles,
                    client=client,
                )
                if not result.authenticated:
                    _raise_for_verify_result(result)
                try:
                    request.user = result.user
                except (AttributeError, TypeError):
                    pass
                return await func(*args, **kwargs)

            return _async_wrapper

        @functools.wraps(func)
        def _sync_wrapper(*args: Any, **kwargs: Any) -> Any:
            request = args[0] if args else kwargs.get("request")
            loop = asyncio.new_event_loop()
            try:
                result = loop.run_until_complete(
                    verify(
                        app_id,
                        cookies=_extract_cookies(request),
                        roles=roles,
                        client=client,
                    )
                )
            finally:
                loop.close()
            if not result.authenticated:
                _raise_for_verify_result(result)
            try:
                request.user = result.user
            except (AttributeError, TypeError):
                pass
            return func(*args, **kwargs)

        return _sync_wrapper

    return decorator
