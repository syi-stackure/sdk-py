# Stackure Python SDK

[![Check build](https://github.com/syi-stackure/sdk-py/actions/workflows/check-build.yml/badge.svg)](https://github.com/syi-stackure/sdk-py/actions/workflows/check-build.yml)
[![PyPI version](https://img.shields.io/pypi/v/stackure.svg)](https://pypi.org/project/stackure/)
[![Python versions](https://img.shields.io/pypi/pyversions/stackure.svg)](https://pypi.org/project/stackure/)
[![PyPI - Downloads](https://img.shields.io/pypi/dm/stackure.svg)](https://pypi.org/project/stackure/)
[![Trusted publisher](https://img.shields.io/badge/pypi-trusted--publisher-blue)](https://docs.pypi.org/trusted-publishers/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)

Passwordless magic-link authentication SDK for Python — drop-in ASGI and WSGI middleware, zero dependencies.

Protect an app with one line, or verify sessions and send magic links directly against the [Stackure](https://stackure.com) auth API.

## Install

```bash
pip install stackure
```

Requires Python 3.14+.

## Protect an app

```python
import stackure

app_id = "7f3c1a2e-9b4d-4e6f-8a1b-2c3d4e5f6071"  # your app's UUID in Stackure

# ASGI — FastAPI, Starlette, Quart
app = stackure.auth(app_id, "can_approve_invoice")(app)

# WSGI — Flask, Django
flask_app.wsgi_app = stackure.auth(app_id, "can_approve_invoice")(flask_app.wsgi_app)
```

The same wrapper handles both; it detects the protocol it was called under.

Access the authenticated user in your view:

```python
user = stackure.user_from_request(request)
print(user.user_email, user.user_permissions)
```

- API requests get JSON errors
- Browser requests get redirected to sign-in
- The sign-in handoff is automatic: Stackure hands the browser back with a `session_token`, the middleware stores it as a cookie on your domain and strips it from the URL

## Requirements

Stackure binds sessions to the browser's user agent and IP. The SDK validates
from your server, so it forwards the original `User-Agent` and
`X-Forwarded-For`. Your app must see the real client IP — if it runs behind a
proxy or CDN, make sure that layer sets `X-Forwarded-For`.

Every request is validated against Stackure, so revocation is immediate.

## Verify manually

```python
result = stackure.verify(app_id, request)

if not result.authenticated:
    # result.error.code, result.error.message, result.error.sign_in_url
    ...

# result.user
```

`verify` never raises — transport and API failures come back as a 500 result.
It accepts a WSGI `environ`, an ASGI `scope`, or a framework request object
(Starlette, FastAPI, Flask, Django).

## Send a magic link

```python
resp = stackure.send_magic_link("user@example.com", app_id)
# resp.message
```

## Log out

```python
r = stackure.logout(request)
```

Returns the status and headers that clear the app's cookie and redirect to
Stackure's sign-out. Your framework builds the response:

```python
# Flask
return "", r.status, r.headers

# Starlette / FastAPI
return Response(status_code=r.status, headers=dict(r.headers))
```

## Configuration

Set `STACKURE_BASE_URL` to point at a non-production environment:

```bash
STACKURE_BASE_URL=https://stage.stackure.com python app.py
```

Retry-on-5xx (one retry after 500ms) and the 2-second request timeout are
hard-coded. Timeouts are never retried.

## Errors

Everything except `verify` raises `StackureError`. Switch on `.code`:

```python
from stackure import StackureError

try:
    stackure.send_magic_link(email)
except StackureError as err:
    match err.code:
        case "validation": ...  # bad input
        case "auth": ...        # 401 from the API
        case "forbidden": ...   # 403 from the API
        case "timeout": ...     # request exceeded the 2s timeout
        case "network": ...     # everything else
```

## Contributing

Open a PR. Tag a release when ready: `git tag vX.Y.Z && git push --tags` — the release workflow builds, signs, and publishes.

## Security

Report vulnerabilities via [GitHub Security Advisories](https://github.com/syi-stackure/sdk-py/security/advisories/new). Releases publish to PyPI via [OIDC trusted publishing](https://docs.pypi.org/trusted-publishers/) with [GitHub build-provenance attestations](https://docs.github.com/en/actions/security-guides/using-artifact-attestations-to-establish-provenance-for-builds).

## License

MIT
