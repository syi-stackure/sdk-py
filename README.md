# Stackure Python SDK

Authentication for your app. One decorator.

## Install

```bash
pip install stackure
```

Requires Python 3.10+.

## Protect a Route

```python
from stackure import auth

@app.get("/admin")
@auth(app_id="my-app-id", roles=["admin"])
async def admin(request):
    return {"user": request.user}
```

Works with FastAPI, Starlette, Django, Flask.

## Verify Manually

```python
from stackure import verify

result = await verify(app_id="my-app-id", cookies=dict(request.cookies))

if not result.authenticated:
    return {"error": result.error["message"]}, result.error["code"]

return {"user": result.user}
```

## Client Functions

```python
import stackure

await stackure.send_magic_link(email="user@example.com", app_id="my-app-id")
await stackure.sign_in("my-app-id", email="user@example.com")

session = await stackure.validate_session("my-app-id", cookies=request.cookies)
# session.authenticated, session.user, session.sign_in_url

await stackure.logout(cookies=request.cookies)
```

## Custom Client

```python
from stackure import StackureClient

client = StackureClient(
    base_url="https://staging.stackure.com",
    timeout=5.0,
)
```

## Errors

`ValidationError` | `NetworkError` | `AuthenticationError` | `ForbiddenError` | `StackureTimeoutError`

```python
from stackure import ValidationError, NetworkError, AuthenticationError, ForbiddenError, StackureTimeoutError
```

## License

MIT
