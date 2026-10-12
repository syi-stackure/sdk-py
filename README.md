# Stackure Python SDK

[![Check build](https://github.com/syi-stackure/sdk-py/actions/workflows/check-build.yml/badge.svg)](https://github.com/syi-stackure/sdk-py/actions/workflows/check-build.yml)
[![PyPI version](https://img.shields.io/pypi/v/stackure.svg)](https://pypi.org/project/stackure/)
[![Python versions](https://img.shields.io/pypi/pyversions/stackure.svg)](https://pypi.org/project/stackure/)
[![PyPI downloads](https://img.shields.io/pypi/dm/stackure.svg)](https://pypi.org/project/stackure/)
[![Trusted publisher](https://img.shields.io/badge/pypi-trusted--publisher-blue)](https://docs.pypi.org/trusted-publishers/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)

Add Stackure sign-in to an ASGI or WSGI app. Zero dependencies.

## Install

```bash
pip install stackure
```

Needs Python 3.14 or later.

## Example

Set `STACKURE_APP_ID` and `STACKURE_APP_SECRET` from the app's page in Stackure, then wrap your ASGI or WSGI app:

```python
import stackure

app = stackure.auth()(app)

# in a view
user = stackure.user_from_request(request)
```

## Documentation

Configuration, sign-in handoff, MCP, sign-out, errors and limits: [stackure.com/docs/python](https://stackure.com/docs/python)

## License

MIT
