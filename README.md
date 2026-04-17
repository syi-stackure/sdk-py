# Stackure Python SDK

[![Check build](https://github.com/syi-stackure/sdk-py/actions/workflows/check-build.yml/badge.svg)](https://github.com/syi-stackure/sdk-py/actions/workflows/check-build.yml)
[![PyPI version](https://img.shields.io/pypi/v/stackure.svg)](https://pypi.org/project/stackure/)
[![Python versions](https://img.shields.io/pypi/pyversions/stackure.svg)](https://pypi.org/project/stackure/)
[![PyPI - Downloads](https://img.shields.io/pypi/dm/stackure.svg)](https://pypi.org/project/stackure/)
[![Trusted publisher](https://img.shields.io/badge/pypi-trusted--publisher-blue)](https://docs.pypi.org/trusted-publishers/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)

Authentication for your app. One decorator.

## Install

```bash
pip install stackure
```

Requires Python 3.10+.

## Protect a route

```python
from stackure import auth

@app.get("/admin")
@auth(app_id="my-app-id", roles=["admin"])
async def admin(request):
    return {"user": request.user}
```

Works with FastAPI, Starlette, Django, Flask, aiohttp — cookies extracted automatically from the request object.

## Verify manually

```python
from stackure import verify

result = await verify(app_id="my-app-id", cookies=dict(request.cookies))

if not result.authenticated:
    return {"error": result.error["message"]}, result.error["code"]

return {"user": result.user}
```

## Send a magic link

```python
from stackure import send_magic_link

await send_magic_link(email="user@example.com", app_id="my-app-id")
```

## Log out

```python
from stackure import logout

await logout(dict(request.cookies))
```

## Configuration

Set `STACKURE_BASE_URL` to point at a non-production environment:

```bash
STACKURE_BASE_URL=https://stage.stackure.com python app.py
```

## Errors

All errors are `StackureError`. Switch on `.code`:

```python
from stackure import StackureError

try:
    await send_magic_link(email=email)
except StackureError as err:
    # err.code is one of: "validation" | "auth" | "forbidden" | "timeout" | "network"
    ...
```

## Contributing

Open a PR. Tag a release when ready: `git tag vX.Y.Z && git push --tags` — the release workflow builds, signs, and publishes.

## Security

Report vulnerabilities via [GitHub Security Advisories](https://github.com/syi-stackure/sdk-py/security/advisories/new). Releases publish to PyPI via [OIDC trusted publishing](https://docs.pypi.org/trusted-publishers/) with [GitHub build-provenance attestations](https://docs.github.com/en/actions/security-guides/using-artifact-attestations-to-establish-provenance-for-builds).

## License

MIT
