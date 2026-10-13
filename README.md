# Stackure Python SDK

[![Check build](https://github.com/syi-stackure/sdk-py/actions/workflows/check-build.yml/badge.svg)](https://github.com/syi-stackure/sdk-py/actions/workflows/check-build.yml)
[![PyPI version](https://img.shields.io/pypi/v/stackure.svg)](https://pypi.org/project/stackure/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)

[Stackure](https://stackure.com) is passwordless auth for B2B apps. This SDK adds it to an ASGI or WSGI app, such as FastAPI, Flask or Django, with zero dependencies.

## Install

```bash
pip install stackure
```

Needs Python 3.14 or later.

## Quickstart

Set `STACKURE_APP_ID` and `STACKURE_APP_SECRET` from the app's page in Stackure, then wrap your ASGI or WSGI app:

```python
import stackure

app = stackure.auth()(app)

# in a view
user = stackure.user_from_request(request)
```

## Docs

- Guide and reference: [stackure.com/docs/python](https://stackure.com/docs/python)
- For AI agents: [stackure.com/llms.txt](https://stackure.com/llms.txt)

## License

MIT
