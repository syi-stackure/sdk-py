# Stackure Python SDK

Official Stackure authentication SDK for Python.

**Authentication that adapts to your app.** Smart defaults with full control when you need it.

[![PyPI version](https://badge.fury.io/py/stackure.svg)](https://pypi.org/project/stackure/)
[![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Installation

```bash
pip install stackure
```

**Requirements:**
- Python 3.10+
- [`httpx`](https://www.python-httpx.org/) (installed automatically)

## Quick Start

```python
import asyncio
import stackure

async def main():
    # Send magic link email
    await stackure.send_magic_link(
        email="user@example.com",
        app_id="your-app-id"
    )

    # Check if user is authenticated (pass cookies from incoming request)
    session = await stackure.validate_session("your-app-id", cookies=request_cookies)
    if session.authenticated:
        print("Welcome:", session.user.user_email)
        print("User ID:", session.user.user_id)
        print("Name:", session.user.user_first_name, session.user.user_last_name)
        print("Roles:", session.user.user_roles)

    # Sign out
    await stackure.logout(cookies=request_cookies)

asyncio.run(main())
```

## Server-Side Protection

### Manual Verification

```python
from stackure import verify

async def protected_route(request):
    result = await verify(
        app_id="your-app-id",
        cookies=dict(request.cookies),
    )

    if not result.authenticated:
        return {"error": result.error["message"]}, result.error["code"]

    return {"user": result.user}
```

### Role-Based Access Control

```python
from stackure import verify

async def admin_route(request):
    result = await verify(
        app_id="your-app-id",
        cookies=dict(request.cookies),
        roles=["admin", "superadmin"],
    )

    if not result.authenticated:
        # 401 if not logged in, 403 if wrong role
        return {"error": result.error["message"]}, result.error["code"]

    return {"admin": True, "user": result.user}
```

### FastAPI Example

```python
from fastapi import FastAPI, Request, HTTPException, Depends
from stackure import verify, StackureUser

app = FastAPI()

async def require_auth(request: Request) -> StackureUser:
    result = await verify(
        app_id="your-app-id",
        cookies=dict(request.cookies),
    )
    if not result.authenticated:
        raise HTTPException(status_code=result.error["code"], detail=result.error["message"])
    return result.user

@app.get("/dashboard")
async def dashboard(user: StackureUser = Depends(require_auth)):
    return {"message": f"Welcome {user.user_email}", "user": user}
```

### `@auth` Decorator

Protect any view function with a single decorator. On success, `request.user` is set
to the authenticated user. On failure, raises `AuthenticationError` (401) or
`ForbiddenError` (403).

Works with **async** and **sync** view functions.

```python
from stackure import auth

# FastAPI / Starlette (async)
@app.get("/dashboard")
@auth(app_id="your-app-id")
async def dashboard(request):
    return {"user": request.user}

# With role enforcement
@app.get("/admin")
@auth(app_id="your-app-id", roles=["admin", "superadmin"])
async def admin_only(request):
    return {"admin": True, "user": request.user}

# Django (sync)
@auth(app_id="your-app-id", roles=["admin"])
def django_view(request):
    return JsonResponse({"user": request.user.user_id})
```

**Note:** the sync path spawns a new event loop. Do not use sync `@auth` inside an
already-running async event loop (e.g., as an ASGI coroutine); use the async form instead.

### Django / Django REST Framework Example

```python
from django.http import JsonResponse
from stackure import verify
import asyncio

def protected_view(request):
    result = asyncio.run(verify(
        app_id="your-app-id",
        cookies=request.COOKIES,
    ))
    if not result.authenticated:
        return JsonResponse({"error": result.error["message"]}, status=result.error["code"])
    return JsonResponse({"user_id": result.user.user_id})
```

## Custom Client

```python
from stackure import StackureClient

client = StackureClient(
    base_url="https://staging.stackure.com",  # default: https://stackure.com
    timeout=5.0,                               # default: 10.0 seconds
)

await client.send_magic_link(email="user@example.com", app_id="your-app-id")
```

## API Reference

### Module-Level Functions

All functions use a shared default client (`base_url="https://stackure.com"`, `timeout=10.0`).

---

#### `send_magic_link(email, app_id=None)`

Send a magic link email for passwordless authentication.

```python
await stackure.send_magic_link(email="user@example.com", app_id="your-app-id")
```

**Parameters:**
- `email` (str, required) — User's email address
- `app_id` (str, optional) — Your Stackure app ID (UUID)

**Returns:** `MagicLinkResponse`

**Raises:**
- `ValidationError` — Invalid email or app ID format
- `NetworkError` — Network request failed
- `StackureTimeoutError` — Request exceeded timeout

---

#### `validate_session(app_id, cookies=None)`

Check if a user has a valid session.

```python
session = await stackure.validate_session("your-app-id", cookies=request.cookies)

if session.authenticated:
    print(session.user.user_id)
    print(session.user.user_email)
    print(session.user.user_roles)
else:
    print(session.sign_in_url)
```

**Parameters:**
- `app_id` (str, required) — Your Stackure app ID (UUID)
- `cookies` (dict, optional) — Session cookies from the incoming request

**Returns:** `SessionValidationResponse`

---

#### `logout(cookies=None)`

Sign out the current user from all Stackure-powered apps.

```python
await stackure.logout(cookies=request.cookies)
```

**Parameters:**
- `cookies` (dict, optional) — Session cookies from the incoming request

---

#### `sign_in(app_id, email=None)`

Initiate authentication flow. If `email` is provided, sends a magic link. Otherwise returns `None` (redirect to sign-in is browser-only).

```python
await stackure.sign_in("your-app-id", email="user@example.com")
```

---

#### `verify(app_id, cookies=None, roles=None, client=None)`

Verify authentication and optionally check roles without raising exceptions.

```python
from stackure import verify

result = await verify(
    app_id="your-app-id",
    cookies=dict(request.cookies),
    roles=["admin"],
)

if result.authenticated:
    print(result.user.user_email)
else:
    print(result.error["code"])     # 401 or 403
    print(result.error["message"])
    print(result.error.get("sign_in_url"))
```

**Parameters:**
- `app_id` (str, required) — Your Stackure app ID
- `cookies` (dict, optional) — Session cookies from the incoming request
- `roles` (list[str], optional) — Required roles. User must have at least one.
- `client` (StackureClient, optional) — Custom client instance

**Returns:** `VerifyResult`

---

### Types

```python
from stackure import StackureUser, MagicLinkResponse, SessionValidationResponse, VerifyResult

# StackureUser
user.user_id           # str
user.user_email        # str
user.user_first_name   # str
user.user_last_name    # str
user.user_roles        # list[str]

# MagicLinkResponse
response.message       # str
response.token         # str | None  (only in local/test environments)

# SessionValidationResponse
session.authenticated  # bool
session.user           # StackureUser | None
session.sign_in_url    # str | None

# VerifyResult
result.authenticated   # bool
result.user            # StackureUser | None
result.error           # dict | None  — keys: code, message, sign_in_url?
```

---

### Error Handling

```python
from stackure import (
    ValidationError,
    NetworkError,
    AuthenticationError,
    StackureTimeoutError,
    StackureError,
)

try:
    await stackure.send_magic_link(email="bad", app_id="your-app-id")
except ValidationError as e:
    print("Invalid input:", e)
except NetworkError as e:
    print("Network failed:", e, "status:", e.status_code)
except StackureTimeoutError:
    print("Request timed out")
except AuthenticationError as e:
    print("Auth failed:", e)
except StackureError as e:
    print("SDK error:", e.code, e)
```

**Error Types:**
- `ValidationError` — Invalid input (email, app ID format)
- `NetworkError` — Request failed (no internet, bad response)
- `AuthenticationError` — 401 from the API
- `ForbiddenError` — 403, user lacks the required role
- `StackureTimeoutError` — Request exceeded timeout
- `StackureError` — Base class for all SDK errors

## Role-Based Access Control

Roles are defined in your Stackure dashboard and returned in `user.user_roles`.

```python
result = await verify(
    app_id="your-app-id",
    cookies=cookies,
    roles=["admin", "superadmin"],  # user must have at least one
)
```

- User must have **at least one** of the listed roles to pass.
- Failed role checks set `result.error["code"]` to `403`.

## Repository

[github.com/Mappstack/stackure](https://github.com/Mappstack/stackure)
