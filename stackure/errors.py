"""Stackure SDK exception hierarchy."""


class StackureError(Exception):
    """Base exception for all Stackure SDK errors.

    Attributes:
        code: Machine-readable error code string.
        status_code: HTTP status code associated with this error, if any.
    """

    def __init__(self, message: str, code: str, status_code: int | None = None):
        """Initialize a StackureError.

        Args:
            message: Human-readable description of the error.
            code: Machine-readable error code.
            status_code: HTTP status code, if applicable.
        """
        super().__init__(message)
        self.code = code
        self.status_code = status_code


class ValidationError(StackureError):
    """Raised when input validation fails before a request is made.

    This error is raised for invalid email formats, malformed UUIDs,
    or other client-side input violations.
    """

    def __init__(self, message: str):
        """Initialize a ValidationError.

        Args:
            message: Description of the validation failure.
        """
        super().__init__(message, "VALIDATION_ERROR", 400)


class NetworkError(StackureError):
    """Raised when an HTTP request fails or the API returns an error response."""

    def __init__(self, message: str, status_code: int | None = None):
        """Initialize a NetworkError.

        Args:
            message: Description of the network or API failure.
            status_code: HTTP status code from the failed response, if available.
        """
        super().__init__(message, "NETWORK_ERROR", status_code)


class AuthenticationError(StackureError):
    """Raised when the API returns a 401 Unauthorized response."""

    def __init__(self, message: str):
        """Initialize an AuthenticationError.

        Args:
            message: Description of the authentication failure.
        """
        super().__init__(message, "AUTHENTICATION_ERROR", 401)


class StackureTimeoutError(StackureError):
    """Raised when an HTTP request exceeds the configured timeout."""

    def __init__(self, message: str = "Request timed out"):
        """Initialize a StackureTimeoutError.

        Args:
            message: Description of the timeout.
        """
        super().__init__(message, "TIMEOUT_ERROR", 408)


class ForbiddenError(StackureError):
    """Raised when the authenticated user lacks the required role or permission."""

    def __init__(self, message: str):
        """Initialize a ForbiddenError.

        Args:
            message: Description of the permission failure.
        """
        super().__init__(message, "FORBIDDEN_ERROR", 403)
