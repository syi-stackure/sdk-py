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

## Configure

```bash
export STACKURE_APP_SECRET=...   # from the app page in Stackure, shown once
```

Sent as `X-App-Secret` on every call. The first call that actually reaches Stackure raises `StackureError("validation")` if it is missing. `STACKURE_BASE_URL` optionally overrides the API host.

A newly registered app is not usable by anyone, even its creator, until it is shared with the organization or assigned to a team in Stackure. Do that before testing sign-in.

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
- The sign-in handoff is automatic: Stackure POSTs a `session_token` (an app-scoped session token valid only for this app) back to your app, the middleware validates it and stores it as a `stackure_session` cookie on your domain (not `session`, which Flask uses for its own session). Handoff bodies over 4 KB are ignored.

## Requirements

Sessions are not bound to the browser's user agent or IP. The SDK still
forwards the original `User-Agent` and `X-Forwarded-For` when validating from
your server, but they are informational only.

Every request with a session token is validated against Stackure, so revocation
is immediate. Requests without a well-formed token get the sign-in URL without a
Stackure call.

Every call has one 2-second deadline covering connect, headers, body and the
single retry. Calls retry once after 500 ms on a 5xx or a connection failure,
never on a timeout. A timeout anywhere, including while reading the body,
raises `StackureError("timeout")`.

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
        case "timeout": ...     # request exceeded the 2s deadline
        case "network": ...     # everything else
```

## Contributing

Open a PR.

## Security

Report vulnerabilities via [GitHub Security Advisories](https://github.com/syi-stackure/sdk-py/security/advisories/new). Releases publish to PyPI via [OIDC trusted publishing](https://docs.pypi.org/trusted-publishers/) with [GitHub build-provenance attestations](https://docs.github.com/en/actions/security-guides/using-artifact-attestations-to-establish-provenance-for-builds).

## License

MIT
