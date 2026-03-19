"""HTTP client for the Stackure authentication API."""

import asyncio

import httpx

from .errors import AuthenticationError, NetworkError, StackureTimeoutError
from .types import MagicLinkResponse, SessionValidationResponse, StackureUser
from .validation import validate_email, validate_uuid

_DEFAULT_BASE_URL = "https://stackure.com"
_DEFAULT_TIMEOUT = 10.0


class StackureClient:
    """Client for the Stackure authentication API.

    Wraps the Stackure REST endpoints for magic-link authentication, session
    validation, and sign-out. All methods are asynchronous and require an
    async context.

    Example:
        >>> client = StackureClient(base_url="https://staging.stackure.com", timeout=5.0)
        >>> response = await client.send_magic_link(email="user@example.com", app_id="...")
    """

    def __init__(self, base_url: str = _DEFAULT_BASE_URL, timeout: float = _DEFAULT_TIMEOUT):
        """Initialize the Stackure client.

        Args:
            base_url: Base URL of the Stackure API.
            timeout: Request timeout in seconds.
        """
        self._base_url = base_url
        self._timeout = timeout

    async def _request(self, method: str, path: str, **kwargs) -> httpx.Response:
        url = f"{self._base_url}{path}"
        _max_retries = 2
        last_error: Exception | None = None

        for attempt in range(_max_retries + 1):
            if attempt > 0:
                # Exponential backoff: 500ms, 1000ms
                await asyncio.sleep(0.5 * (2 ** (attempt - 1)))
            try:
                async with httpx.AsyncClient(timeout=self._timeout) as http_client:
                    response = await http_client.request(method, url, **kwargs)
                # Retry 5xx errors unless this is the last attempt.
                if response.status_code >= 500 and attempt < _max_retries:
                    last_error = NetworkError(f"Server error ({response.status_code})", response.status_code)
                    continue
                return response
            except httpx.TimeoutException:
                # Timeouts are not retried — a second attempt would obscure latency.
                raise StackureTimeoutError(f"Request timed out after {self._timeout}s")
            except httpx.RequestError as e:
                last_error = NetworkError(f"Network request failed: {e}")

        raise last_error or NetworkError("Request failed after retries")

    def _handle_response(self, response: httpx.Response) -> dict:
        if not response.is_success:
            try:
                error_text = response.text
            except Exception:
                error_text = "Unknown error"
            if response.status_code == 401:
                raise AuthenticationError(error_text or "Authentication failed")
            raise NetworkError(f"API error ({response.status_code}): {error_text}", response.status_code)
        try:
            return response.json()
        except Exception as exc:
            raise NetworkError("Invalid JSON response from server") from exc

    async def send_magic_link(self, email: str, app_id: str | None = None) -> MagicLinkResponse:
        """Send a magic-link authentication email to a user.

        Args:
            email: Recipient's email address.
            app_id: Your Stackure application UUID.

        Returns:
            A :class:`MagicLinkResponse` with the API's status message.

        Raises:
            ValidationError: If ``email`` or ``app_id`` fails format validation.
            NetworkError: If the request fails or the API returns an error.
            StackureTimeoutError: If the request exceeds the configured timeout.
        """
        validate_email(email)
        if app_id:
            validate_uuid(app_id, "App ID")
        body: dict = {"user_email": email}
        if app_id:
            body["app_id"] = app_id
        response = await self._request("POST", "/api/public/auth/magic-link/send", json=body)
        data = self._handle_response(response)
        try:
            return MagicLinkResponse(message=data["message"], token=data.get("token"))
        except KeyError as exc:
            raise NetworkError("Unexpected API response format") from exc

    async def validate_session(self, app_id: str, cookies: dict | None = None) -> SessionValidationResponse:
        """Validate the current session for an application.

        Args:
            app_id: Your Stackure application UUID.
            cookies: Session cookies from the incoming HTTP request. Pass
                ``dict(request.cookies)`` from your web framework.

        Returns:
            A :class:`SessionValidationResponse` containing authentication status
            and user details when authenticated.

        Raises:
            ValidationError: If ``app_id`` fails format validation.
            NetworkError: If the request fails or the API returns an error.
            StackureTimeoutError: If the request exceeds the configured timeout.
        """
        validate_uuid(app_id, "App ID")
        response = await self._request(
            "GET",
            "/api/public/auth/session/validate",
            params={"app_id": app_id},
            cookies=cookies,
        )
        data = self._handle_response(response)
        try:
            user = None
            if data.get("user"):
                u = data["user"]
                user = StackureUser(
                    user_id=u["user_id"],
                    user_email=u["user_email"],
                    user_first_name=u["user_first_name"],
                    user_last_name=u["user_last_name"],
                    user_roles=u.get("user_roles", []),
                )
            return SessionValidationResponse(
                authenticated=data["authenticated"],
                user=user,
                sign_in_url=data.get("sign_in_url"),
            )
        except KeyError as exc:
            raise NetworkError("Unexpected API response format") from exc

    async def logout(self, cookies: dict | None = None) -> None:
        """Sign out the current user from all Stackure applications.

        Args:
            cookies: Session cookies from the incoming HTTP request.

        Raises:
            NetworkError: If the request fails or the API returns an error.
            StackureTimeoutError: If the request exceeds the configured timeout.
        """
        response = await self._request("POST", "/api/public/auth/sign-out", cookies=cookies)
        self._handle_response(response)

    async def sign_in(self, app_id: str, email: str | None = None) -> MagicLinkResponse | None:
        """Initiate sign-in for a user.

        When ``email`` is provided, sends a magic-link directly. When omitted,
        returns ``None``; callers in browser environments should redirect to
        the ``sign_in_url`` returned by :meth:`validate_session`.

        Args:
            app_id: Your Stackure application UUID.
            email: User's email address for direct magic-link delivery.

        Returns:
            A :class:`MagicLinkResponse` if ``email`` was provided, otherwise ``None``.

        Raises:
            ValidationError: If ``app_id`` or ``email`` fails format validation.
            NetworkError: If the request fails or the API returns an error.
            StackureTimeoutError: If the request exceeds the configured timeout.
        """
        validate_uuid(app_id, "App ID")
        if email:
            return await self.send_magic_link(email, app_id)
        return None
