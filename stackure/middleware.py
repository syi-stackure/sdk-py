"""Authentication verification and decorator for web frameworks."""

import asyncio
import functools
import inspect
import logging
from collections.abc import Callable
from typing import Any

from .client import _validate_session
from .errors import StackureError
from .types import VerifyResult

_logger = logging.getLogger(__name__)


async def verify(
    app_id: str,
    cookies: dict | None = None,
    roles: list[str] | None = None,
) -> VerifyResult:
    """Check whether ``cookies`` hold a valid session for ``app_id``.

    Returns a :class:`VerifyResult` without raising; callers inspect the
    result and decide how to respond.

    Args:
        app_id: Your Stackure application UUID.
        cookies: Session cookies from the incoming HTTP request.
        roles: Optional required roles. The user must hold at least one.

    Example:
        >>> result = await verify(app_id="...", cookies=dict(request.cookies))
        >>> if not result.authenticated:
        ...     return {"error": result.error["message"]}, result.error["code"]
        >>> return {"user": result.user}
    """
    try:
        session = await _validate_session(app_id, cookies)
        if not session["authenticated"] or not session["user"]:
            return VerifyResult(
                authenticated=False,
                error={
                    "code": 401,
                    "message": "Valid authentication required",
                    "sign_in_url": session["sign_in_url"],
                },
            )
        user = session["user"]
        if roles and not any(role in user.user_roles for role in roles):
            return VerifyResult(
                authenticated=False,
                user=user,
                error={"code": 403, "message": f"Requires one of: {', '.join(roles)}"},
            )
        return VerifyResult(authenticated=True, user=user)
    except Exception as e:
        _logger.error("stackure: verification error: %s", e)
        return VerifyResult(
            authenticated=False,
            error={"code": 500, "message": "Authentication verification failed"},
        )


def _extract_cookies(request: Any) -> dict:
    """Pull cookies off any framework's request object.

    Works with FastAPI, Starlette, Flask, aiohttp (``cookies`` attr) and
    Django (``COOKIES`` attr). Returns an empty dict if nothing is found.
    """
    if request is None:
        return {}
    cookies = getattr(request, "cookies", None) or getattr(request, "COOKIES", None)
    return dict(cookies) if cookies else {}


def auth(app_id: str, roles: list[str] | None = None) -> Callable:
    """Decorator enforcing authentication on a view.

    On success, attaches the authenticated :class:`~stackure.User` to
    ``request.user`` (when the request object accepts attribute assignment).
    On failure, raises :class:`~stackure.StackureError` — your framework's
    exception handling turns it into the appropriate HTTP response.

    Supports both synchronous and asynchronous view functions.

    Args:
        app_id: Your Stackure application UUID.
        roles: Optional required roles.

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
                )
                if not result.authenticated:
                    _raise(result)
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
                    verify(app_id, cookies=_extract_cookies(request), roles=roles),
                )
            finally:
                loop.close()
            if not result.authenticated:
                _raise(result)
            try:
                request.user = result.user
            except (AttributeError, TypeError):
                pass
            return func(*args, **kwargs)

        return _sync_wrapper

    return decorator


def _raise(result: VerifyResult) -> None:
    """Translate a failed :class:`VerifyResult` into a :class:`StackureError`."""
    code = result.error["code"] if result.error else 401
    message = result.error["message"] if result.error else "Authentication required"
    if code == 403:
        raise StackureError("forbidden", message, 403)
    raise StackureError("auth", message, code)
