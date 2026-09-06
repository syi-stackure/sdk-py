"""Data types used by the Stackure SDK."""

from collections.abc import Mapping
from dataclasses import dataclass, field


@dataclass(frozen=True)
class User:
    """An authenticated Stackure user.

    Attributes:
        user_id: Unique identifier for the user.
        user_email: User's email address.
        user_first_name: User's first name.
        user_last_name: User's last name.
        user_permissions: Permissions granted to the user for the current app.
    """

    user_id: str
    user_email: str
    user_first_name: str
    user_last_name: str
    user_permissions: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class MagicLinkResponse:
    """Successful :func:`send_magic_link` response.

    Attributes:
        message: Human-readable confirmation string from the API.
    """

    message: str


@dataclass(frozen=True)
class VerifyError:
    """Why a :func:`verify` call did not authenticate.

    Attributes:
        code: HTTP status code — 401, 403, or 500.
        message: Human-readable description.
        sign_in_url: Where to send an unauthenticated browser to sign in.
    """

    code: int
    message: str
    sign_in_url: str = ""


@dataclass(frozen=True)
class VerifyResult:
    """Outcome of a :func:`verify` call.

    Attributes:
        authenticated: Whether the request carries a valid session.
        user: The user, when authenticated (also set on a 403).
        error: Populated when ``authenticated`` is ``False``.
    """

    authenticated: bool = False
    user: "User | None" = None
    error: "VerifyError | None" = None


@dataclass(frozen=True)
class Session:
    """Raw :func:`validate_session` response.

    Attributes:
        authenticated: Whether Stackure recognised the session.
        user: The user, when authenticated.
        sign_in_url: Where to send the browser to sign in, when not.
    """

    authenticated: bool = False
    user: "User | None" = None
    sign_in_url: str = ""


@dataclass(frozen=True)
class Request:
    """Normalised view of an incoming HTTP request.

    Built automatically from a WSGI ``environ``, an ASGI ``scope``, or a
    framework request object. You rarely construct one yourself.

    Attributes:
        method: Uppercase HTTP method.
        path: Full request path, including any mount prefix.
        query: Raw query string, without the leading ``?``.
        headers: Request headers, keyed by lowercase name.
        remote_addr: Peer address, before ``X-Forwarded-For`` is considered.
        scheme: ``"http"`` or ``"https"``.
    """

    method: str = "GET"
    path: str = "/"
    query: str = ""
    headers: Mapping[str, str] = field(default_factory=dict)
    remote_addr: str = ""
    scheme: str = "http"


@dataclass(frozen=True)
class Redirect:
    """Response returned by :func:`logout`.

    Attributes:
        status: HTTP status code to send.
        headers: Response headers to send, as ``(name, value)`` pairs.
    """

    status: int
    headers: list[tuple[str, str]]
