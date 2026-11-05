# Stackure Python SDK

[![Check build](https://github.com/syi-stackure/sdk-py/actions/workflows/check-build.yml/badge.svg)](https://github.com/syi-stackure/sdk-py/actions/workflows/check-build.yml)
[![PyPI version](https://img.shields.io/pypi/v/stackure.svg)](https://pypi.org/project/stackure/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)

[Stackure](https://stackure.com) is sign-in and app access for your people and your partners. This SDK adds it to an ASGI or WSGI app, such as FastAPI, Flask or Django, with zero dependencies.

## Install

```bash
pip install stackure
```

Needs Python 3.14 or later.

## Quickstart

Set `STACKURE_APP_ID` and `STACKURE_APP_SECRET` from the app's page in Stackure and `STACKURE_BASE_URL` to your region's address, `https://eu.stackure.com` or `https://us.stackure.com`, then wrap your ASGI or WSGI app:

```python
import stackure

app = stackure.auth()(app)

# or only /admin and everything under it
app = stackure.auth("/admin")(app)

# in a view
user = stackure.user_from_request(request)
```

## Docs

- Guide and reference: [stackure.com/docs/python](https://stackure.com/docs/python)
- For AI agents: [stackure.com/llms.txt](https://stackure.com/llms.txt)

## Model

Modeled in Mappstack as the Stackure project. Every change starts in the model, then the code follows it.

## License

MIT
