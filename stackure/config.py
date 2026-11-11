"""Fixed values, and the environment the SDK reads once on first use."""

import os
import sys
import threading
import urllib.parse
from dataclasses import dataclass

from .errors import StackureError
from .validation import is_loopback_host, is_uuid

REQUEST_TIMEOUT_S = 2.0
MAX_RETRIES = 1
RETRY_DELAY_S = 0.5
MAX_EVENTS = 100
LOOP_CHECK_S = 1.0
MAX_HANDOFF_BODY = 4096

SESSION_COOKIE = "stackure_session"
PLATFORM_COOKIE = "session"
CODE_COOKIE = "stackure_code"
VERIFIER_COOKIE = "stackure_verifier"
TOKEN_PARAM = "session_token"
CODE_PARAM = "stackure_code"
SESSION_MAX_AGE = 604800
CODE_MAX_AGE = 60
VERIFIER_MAX_AGE = 900
VERIFIER_BYTES = 32
USER_KEY = "stackure.user"

MAGIC_LINK_PATH = "/api/public/auth/magic-link/send"
VALIDATE_PATH = "/api/public/auth/session/validate"
EXCHANGE_PATH = "/api/public/auth/session/exchange"
DIRECTORY_USERS_PATH = "/api/public/directory/users"
DIRECTORY_TEAMS_PATH = "/api/public/directory/teams"
EVENTS_PATH = "/api/public/events"
SIGN_OUT_PATH = "/api/public/auth/sign-out"
SIGN_IN_PAGE = "/sign-in/magic-link"
SIGN_OUT_PAGE = "/signout"
HOME_PAGE = "/"

_INVALID_BASE_URL = (
    "invalid STACKURE_BASE_URL format (must be an https URL, or http on localhost or 127.0.0.1)"
)


@dataclass(frozen=True)
class _Env:
    base_url: str
    base_url_error: str
    origin: str
    app_id: str
    app_id_error: str
    app_secret: str
    app_secret_error: str


def _read_base_url() -> tuple[str, str, str]:
    raw = os.environ.get("STACKURE_BASE_URL", "").rstrip("/")
    if not raw:
        return "", "STACKURE_BASE_URL is not set", ""
    if "?" in raw or "#" in raw:
        return "", _INVALID_BASE_URL, ""
    try:
        u = urllib.parse.urlsplit(raw)
        _ = u.port
    except ValueError:
        return "", _INVALID_BASE_URL, ""
    host = u.netloc.rpartition("@")[2].lower()
    secure = u.scheme == "https" or (u.scheme == "http" and is_loopback_host(host))
    if not u.hostname or not secure:
        return "", _INVALID_BASE_URL, ""
    return raw, "", f"{u.scheme}://{host}"


def _read() -> _Env:
    base, base_error, origin = _read_base_url()
    app = os.environ.get("STACKURE_APP_ID", "")
    secret = os.environ.get("STACKURE_APP_SECRET", "")
    if not app:
        app_error = "STACKURE_APP_ID is not set"
    elif not is_uuid(app):
        app_error = "invalid STACKURE_APP_ID format (must be a valid UUID)"
    else:
        app_error = ""
    return _Env(
        base_url=base,
        base_url_error=base_error,
        origin=origin,
        app_id=app,
        app_id_error=app_error,
        app_secret=secret,
        app_secret_error="" if secret else "STACKURE_APP_SECRET is not set",
    )


_lock = threading.Lock()
_env: _Env | None = None

if sys.platform != "win32":
    os.register_at_fork(
        before=_lock.acquire, after_in_parent=_lock.release, after_in_child=_lock.release
    )


def _loaded() -> _Env:
    global _env
    if _env is None:
        with _lock:
            if _env is None:
                _env = _read()
    return _env


def base_url() -> str:
    """``STACKURE_BASE_URL`` without its trailing ``/``, or ``""`` when unset or invalid."""
    return _loaded().base_url


def required_base_url() -> str:
    """``STACKURE_BASE_URL``. Raises ``"validation"`` when unset or invalid."""
    env = _loaded()
    if env.base_url_error:
        raise StackureError("validation", env.base_url_error)
    return env.base_url


def origin() -> str:
    """The scheme and host of ``STACKURE_BASE_URL``."""
    return _loaded().origin


def app_id() -> str:
    """``STACKURE_APP_ID``. Raises ``"validation"`` when unset or not a UUID v4."""
    env = _loaded()
    if env.app_id_error:
        raise StackureError("validation", env.app_id_error)
    return env.app_id


def app_secret() -> str:
    """``STACKURE_APP_SECRET``. Raises ``"validation"`` when unset."""
    env = _loaded()
    if env.app_secret_error:
        raise StackureError("validation", env.app_secret_error)
    return env.app_secret


def app_secret_if_set() -> str:
    """``STACKURE_APP_SECRET``, or ``""`` when unset."""
    return _loaded().app_secret
