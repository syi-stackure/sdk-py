"""Tests for :func:`stackure.mcp` against a local stand-in for Stackure."""

import asyncio
import dataclasses
import http.client
import http.server
import json
import os
import threading
import time
import unittest
import urllib.parse
import wsgiref.simple_server
from typing import Any
from unittest import mock

import stackure
from stackure import client

TOKEN = "0b9f6c1e-3a7d-4c58-9e21-6d4f8a2b7c10"
OTHER = "5d2e8f4a-1c3b-4a79-b6e0-9f8d7c6b5a41"
APP_ID = "7f3c1a2e-9b4d-4e6f-8a1b-2c3d4e5f6071"
SECRET = "app-secret-under-test"
HOST = "app.example.com"
VALIDATE = "/api/public/auth/session/validate"
TARGET = f"{VALIDATE}?app_id={APP_ID}&mcp=http%3A%2F%2F{HOST}%2Fmcp"
CHALLENGE = (
    'Bearer resource_metadata="https://stackure.example/.well-known/oauth-protected-resource'
    f'/mcp/{APP_ID}?resource=http%3A%2F%2F{HOST}%2Fmcp"'
)
USER = stackure.User(
    user_id="3c9a7e52-6b1d-4f08-a2c4-8e5d1f7b9a63",
    account_id="a1f4c8d2-7e3b-4956-8d0a-2b6c9e4f1d37",
    user_email="ada@example.com",
    user_first_name="Ada",
    user_last_name="Lovelace",
    user_permissions=["can_read_invoice", "can_approve_invoice"],
)
JSON = {"Content-Type": "application/json"}
SIGNED_IN = (
    200,
    JSON,
    json.dumps({"authenticated": True, "user": dataclasses.asdict(USER)}).encode(),
)
SIGNED_OUT = (
    200,
    JSON,
    json.dumps(
        {
            "authenticated": False,
            "sign_in_url": f"https://stackure.example/sign-in/magic-link?app_id={APP_ID}",
            "www_authenticate": CHALLENGE,
        }
    ).encode(),
)
FAILED = "ERROR:stackure.middleware:stackure: mcp verification failed: "

Response = tuple[int, dict[str, str], bytes]


def _answer(status: int, error: str, **extra: str) -> Response:
    body = f'{{"error":"{error}"}}'.encode()
    return (
        status,
        {**extra, "content-type": "application/json", "content-length": str(len(body))},
        body,
    )


PASSED: Response = (200, {"content-length": "2"}, b"ok")
UNAUTHORIZED = _answer(401, "unauthorized", **{"www-authenticate": CHALLENGE})
FORBIDDEN = _answer(403, "forbidden")
UNAVAILABLE = _answer(503, "unavailable")


def _stackure(headers: Any) -> tuple[int, dict[str, str], bytes]:
    cookie = headers["Cookie"] or ""
    if TOKEN in cookie or headers["Authorization"] == f"Bearer {TOKEN}":
        return SIGNED_IN
    return SIGNED_OUT


class _Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        server: Any = self.server
        server.seen.append((self.command, self.path, self.headers))
        time.sleep(server.delay)
        reply = server.reply
        status, headers, body = reply(self.headers) if callable(reply) else reply
        self.send_response(status)
        for name, value in headers.items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: Any) -> None:
        pass


class _Server(http.server.ThreadingHTTPServer):
    def handle_error(self, request: Any, client_address: Any) -> None:
        pass


class _Quiet(wsgiref.simple_server.WSGIRequestHandler):
    def log_message(self, format: str, *args: Any) -> None:
        pass


class McpTest(unittest.TestCase):
    def setUp(self) -> None:
        self.server: Any = _Server(("127.0.0.1", 0), _Handler)
        self.server.seen, self.server.delay, self.server.reply = [], 0, _stackure
        threading.Thread(target=self.server.serve_forever, args=(0.01,), daemon=True).start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.base = f"http://127.0.0.1:{self.server.server_port}"
        env = mock.patch.dict(
            os.environ, {"STACKURE_BASE_URL": self.base, "STACKURE_APP_SECRET": SECRET}
        )
        env.start()
        self.addCleanup(env.stop)
        self.users: list[stackure.User | None] = []

    def wsgi(self, environ: dict[str, Any], *permissions: str, app_id: str = APP_ID) -> Response:
        def app(environ: dict[str, Any], start_response: Any) -> list[bytes]:
            self.users.append(stackure.user_from_request(environ))
            start_response("200 OK", [("Content-Length", "2")])
            return [b"ok"]

        sent: list[tuple[str, list[tuple[str, str]]]] = []
        chunks = stackure.mcp(app_id, *permissions)(app)(
            environ, lambda status, headers: sent.append((status, headers))
        )
        [(status, headers)] = sent
        return int(status.split()[0]), {k.lower(): v for k, v in headers}, b"".join(chunks)

    def asgi(self, scope: dict[str, Any], *permissions: str, app_id: str = APP_ID) -> Response:
        async def app(scope: dict[str, Any], receive: Any, send: Any) -> None:
            self.users.append(stackure.user_from_request(scope))
            await send(
                {
                    "type": "http.response.start",
                    "status": 200,
                    "headers": [(b"content-length", b"2")],
                }
            )
            await send({"type": "http.response.body", "body": b"ok"})

        sent: list[dict[str, Any]] = []

        async def receive() -> dict[str, Any]:
            return {"type": "http.request", "body": b"", "more_body": False}

        async def send(message: dict[str, Any]) -> None:
            sent.append(message)

        asyncio.run(stackure.mcp(app_id, *permissions)(app)(scope, receive, send))
        start, *rest = sent
        return (
            start["status"],
            {k.decode(): v.decode() for k, v in start["headers"]},
            b"".join(m["body"] for m in rest),
        )

    def call(
        self,
        *permissions: str,
        authorization: str | None = f"Bearer {TOKEN}",
        cookie: str | None = None,
        host: str = HOST,
        path: str = "/mcp",
        query: str = "",
        scheme: str = "http",
        proto: str | None = None,
        app_id: str = APP_ID,
        asgi: bool = False,
    ) -> Response:
        lines = [
            (name, value)
            for name, value in (
                ("host", host),
                ("authorization", authorization),
                ("cookie", cookie),
                ("x-forwarded-proto", proto),
                ("user-agent", "claude/1"),
            )
            if value is not None
        ]
        self.users = []
        if asgi:
            return self.asgi(
                {
                    "type": "http",
                    "method": "POST",
                    "scheme": scheme,
                    "path": path,
                    "query_string": query.encode(),
                    "client": ("203.0.113.7", 50000),
                    "headers": [(name.encode(), value.encode()) for name, value in lines],
                },
                *permissions,
                app_id=app_id,
            )
        environ = {
            "REQUEST_METHOD": "POST",
            "wsgi.url_scheme": scheme,
            "PATH_INFO": path.encode().decode("latin-1"),
            "QUERY_STRING": query,
            "REMOTE_ADDR": "203.0.113.7",
        }
        for name, value in lines:
            environ["HTTP_" + name.upper().replace("-", "_")] = value
        return self.wsgi(environ, *permissions, app_id=app_id)

    def mcp_url(self) -> str:
        [(_, path, _)] = self.server.seen
        target = urllib.parse.urlsplit(path)
        self.assertEqual(target.path, VALIDATE)
        query = urllib.parse.parse_qs(target.query, keep_blank_values=True, strict_parsing=True)
        self.assertEqual(sorted(query), ["app_id", "mcp"])
        self.assertEqual(query["app_id"], [APP_ID])
        [url] = query["mcp"]
        return url

    def test_valid_bearer_is_validated_and_the_user_attached(self) -> None:
        for asgi in (False, True):
            for scheme in ("Bearer", "bearer", "BEARER", "bEaReR", "Bearer "):
                with self.subTest(asgi=asgi, scheme=scheme):
                    with self.assertNoLogs("stackure", level="DEBUG"):
                        self.server.seen = []
                        result = self.call(
                            authorization=f"{scheme} {TOKEN}",
                            cookie=f"stackure_session={OTHER}; session={OTHER}",
                            asgi=asgi,
                        )
                        self.assertEqual(result, PASSED)
                        self.assertEqual(self.users, [USER])
                        [(method, path, headers)] = self.server.seen
                        self.assertEqual((method, path), ("GET", TARGET))
                        self.assertEqual(headers["X-App-Secret"], SECRET)
                        self.assertEqual(headers["Authorization"], f"Bearer {TOKEN}")
                        self.assertIsNone(headers["Cookie"])
                        self.assertNotIn(OTHER, str(headers))
                        self.assertEqual(headers["User-Agent"], "claude/1")
                        self.assertEqual(headers["X-Forwarded-For"], "203.0.113.7")

    def test_missing_or_malformed_bearer_is_401_with_the_challenge(self) -> None:
        for asgi in (False, True):
            for authorization in (
                None,
                "",
                "Bearer",
                "Bearer ",
                "Bearer abc",
                f"Bearer {TOKEN[:-1]}",
                f"Bearer {TOKEN}0",
                f"Bearer {TOKEN.replace('-4c58-', '-1c58-')}",
                f"Bearer {TOKEN} {TOKEN}",
                f"Bearer {TOKEN},Bearer {TOKEN}",
                f"Bearer token={TOKEN}",
                f"Bearer{TOKEN}",
                f"Basic {TOKEN}",
                f"Token {TOKEN}",
                TOKEN,
            ):
                with self.subTest(asgi=asgi, authorization=authorization):
                    with self.assertNoLogs("stackure", level="DEBUG"):
                        self.server.seen = []
                        result = self.call(authorization=authorization, asgi=asgi)
                        self.assertEqual(result, UNAUTHORIZED)
                        self.assertEqual(self.users, [])
                        self.assertEqual(self.mcp_url(), f"http://{HOST}/mcp")
                        [(_, _, headers)] = self.server.seen
                        self.assertIsNone(headers["Authorization"])
                        self.assertIsNone(headers["Cookie"])
                        self.assertEqual(headers["X-App-Secret"], SECRET)
                        self.assertNotIn(TOKEN[:-1], str(headers))

    def test_bearer_stackure_does_not_recognise_is_401(self) -> None:
        for asgi in (False, True):
            with self.subTest(asgi=asgi), self.assertNoLogs("stackure", level="DEBUG"):
                self.server.seen = []
                result = self.call(authorization=f"Bearer {OTHER}", asgi=asgi)
                self.assertEqual(result, UNAUTHORIZED)
                self.assertEqual(self.users, [])
                [(_, _, headers)] = self.server.seen
                self.assertEqual(headers["Authorization"], f"Bearer {OTHER}")

    def test_session_cookie_without_bearer_is_ignored(self) -> None:
        for asgi in (False, True):
            for authorization in (None, "Bearer abc", f"Basic {TOKEN}"):
                with self.subTest(asgi=asgi, authorization=authorization):
                    with self.assertNoLogs("stackure", level="DEBUG"):
                        self.server.seen = []
                        result = self.call(
                            authorization=authorization,
                            cookie=f"theme=dark; stackure_session={TOKEN}; session={TOKEN}",
                            asgi=asgi,
                        )
                        self.assertEqual(result, UNAUTHORIZED)
                        self.assertEqual(self.users, [])
                        [(_, _, headers)] = self.server.seen
                        self.assertIsNone(headers["Cookie"])
                        self.assertIsNone(headers["Authorization"])
                        self.assertNotIn(TOKEN, str(headers))

    def test_missing_challenge_falls_back_to_bearer(self) -> None:
        bare = _answer(401, "unauthorized", **{"www-authenticate": "Bearer"})
        for reply in (
            b'{"authenticated": false}',
            b'{"authenticated": false, "www_authenticate": ""}',
            b'{"authenticated": true}',
        ):
            for asgi in (False, True):
                with self.subTest(reply=reply, asgi=asgi):
                    with self.assertNoLogs("stackure", level="DEBUG"):
                        self.server.reply = (200, JSON, reply)
                        result = self.call(asgi=asgi)
                        self.assertEqual(result, bare)
                        self.assertEqual(self.users, [])

    def test_missing_permission_is_403(self) -> None:
        for asgi in (False, True):
            with self.subTest(asgi=asgi), self.assertNoLogs("stackure", level="DEBUG"):
                result = self.call("can_delete_invoice", "can_void_invoice", asgi=asgi)
                self.assertEqual(result, FORBIDDEN)
                self.assertEqual(self.users, [])
                result = self.call("can_delete_invoice", "can_approve_invoice", asgi=asgi)
                self.assertEqual(result, PASSED)
                self.assertEqual(self.users, [USER])

    def test_user_without_permissions_is_403_only_when_one_is_required(self) -> None:
        user = dataclasses.asdict(USER)
        del user["user_permissions"]
        self.server.reply = (200, JSON, json.dumps({"authenticated": True, "user": user}).encode())
        for asgi in (False, True):
            with self.subTest(asgi=asgi), self.assertNoLogs("stackure", level="DEBUG"):
                self.assertEqual(self.call("can_approve_invoice", asgi=asgi), FORBIDDEN)
                self.assertEqual(self.users, [])
                self.assertEqual(self.call(asgi=asgi), PASSED)
                self.assertEqual(self.users, [dataclasses.replace(USER, user_permissions=[])])

    def test_validate_error_is_503(self) -> None:
        leak = f'{{"error": "{TOKEN} {SECRET}"}}'.encode()
        for asgi in (False, True):
            for reply, code in (
                ((400, JSON, leak), "network"),
                ((401, JSON, leak), "auth"),
                ((403, JSON, leak), "forbidden"),
                ((429, JSON, leak), "network"),
                ((500, JSON, leak), "network"),
                ((302, {"Location": self.base + "/elsewhere"}, b""), "network"),
                ((200, JSON, b"not json"), "network"),
                ((200, JSON, b"[]"), "AttributeError"),
                ((200, JSON, b'{"authenticated": true, "user": {"user_id": "x"}}'), "network"),
            ):
                with self.subTest(asgi=asgi, reply=reply):
                    self.server.seen, self.server.reply = [], reply
                    with self.assertLogs("stackure", level="DEBUG") as logs:
                        result = self.call(asgi=asgi)
                    self.assertEqual(result, UNAVAILABLE)
                    self.assertEqual(self.users, [])
                    self.assertEqual(logs.output, [FAILED + code])
                    self.assertEqual({path for _, path, _ in self.server.seen}, {TARGET})

    def test_network_error_is_503(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        for asgi in (False, True):
            with self.subTest(asgi=asgi):
                with self.assertLogs("stackure", level="DEBUG") as logs:
                    result = self.call(asgi=asgi)
                self.assertEqual(result, UNAVAILABLE)
                self.assertEqual(self.users, [])
                self.assertEqual(logs.output, [FAILED + "network"])
        self.assertEqual(self.server.seen, [])

    def test_timeout_is_503(self) -> None:
        self.server.delay = 1
        for asgi in (False, True):
            with self.subTest(asgi=asgi), mock.patch.object(client, "_REQUEST_TIMEOUT_S", 0.2):
                with self.assertLogs("stackure", level="DEBUG") as logs:
                    result = self.call(asgi=asgi)
                self.assertEqual(result, UNAVAILABLE)
                self.assertEqual(self.users, [])
                self.assertEqual(logs.output, [FAILED + "timeout"])

    def test_missing_app_secret_or_bad_app_id_is_503_without_a_call(self) -> None:
        for asgi in (False, True):
            with self.subTest(asgi=asgi):
                with self.assertLogs("stackure", level="DEBUG") as logs:
                    result = self.call(app_id="not-a-uuid", asgi=asgi)
                self.assertEqual(result, UNAVAILABLE)
                self.assertEqual(logs.output, [FAILED + "validation"])
                with mock.patch.dict(os.environ):
                    del os.environ["STACKURE_APP_SECRET"]
                    with self.assertLogs("stackure", level="DEBUG") as logs:
                        result = self.call(asgi=asgi)
                self.assertEqual(result, UNAVAILABLE)
                self.assertEqual(logs.output, [FAILED + "validation"])
                self.assertEqual(self.users, [])
        self.assertEqual(self.server.seen, [])

    def test_https_is_reflected_in_the_mcp_url(self) -> None:
        for asgi in (False, True):
            for scheme, proto, expected in (
                ("http", None, "http"),
                ("http", "http", "http"),
                ("https", None, "https"),
                ("https", "http", "https"),
                ("http", "https", "https"),
                ("http", "HTTPS", "https"),
            ):
                with self.subTest(asgi=asgi, scheme=scheme, proto=proto):
                    with self.assertNoLogs("stackure", level="DEBUG"):
                        self.server.seen = []
                        result = self.call(scheme=scheme, proto=proto, asgi=asgi)
                        self.assertEqual(result, PASSED)
                        self.assertEqual(self.mcp_url(), f"{expected}://{HOST}/mcp")

    def test_path_is_in_the_mcp_url_and_the_query_string_is_not(self) -> None:
        for asgi in (False, True):
            for host, path, query, expected in (
                (HOST, "/mcp", "session=1&mcp=https://evil.example/mcp", f"http://{HOST}/mcp"),
                (HOST, "/", "a=b", f"http://{HOST}/"),
                (HOST, "/api/v1/mcp/", "a=b#c", f"http://{HOST}/api/v1/mcp/"),
                ("localhost:8000", "/mcp/sse", "", "http://localhost:8000/mcp/sse"),
                ("[::1]:8000", "/mcp", "", "http://[::1]:8000/mcp"),
                (HOST, "/mcp/a b&c=d#e?f", "g=h", f"http://{HOST}/mcp/a%20b&c=d%23e%3Ff"),
                (HOST, "/mcp/café", "", f"http://{HOST}/mcp/caf%C3%A9"),
            ):
                with self.subTest(asgi=asgi, host=host, path=path, query=query):
                    with self.assertNoLogs("stackure", level="DEBUG"):
                        self.server.seen = []
                        result = self.call(host=host, path=path, query=query, asgi=asgi)
                        self.assertEqual(result, PASSED)
                        self.assertEqual(self.mcp_url(), expected)

    def test_wsgi_mount_prefix_is_in_the_mcp_url(self) -> None:
        environ = {
            "REQUEST_METHOD": "POST",
            "wsgi.url_scheme": "https",
            "SCRIPT_NAME": "/mcp",
            "PATH_INFO": "/messages",
            "QUERY_STRING": "session_id=1",
            "HTTP_HOST": HOST,
            "HTTP_AUTHORIZATION": f"Bearer {TOKEN}",
        }
        with self.assertNoLogs("stackure", level="DEBUG"):
            self.assertEqual(self.wsgi(environ), PASSED)
        self.assertEqual(self.users, [USER])
        self.assertEqual(self.mcp_url(), f"https://{HOST}/mcp/messages")

    def test_asgi_non_http_scope_passes_through(self) -> None:
        seen: list[str] = []

        async def app(scope: dict[str, Any], receive: Any, send: Any) -> None:
            seen.append(scope["type"])

        with self.assertNoLogs("stackure", level="DEBUG"):
            asyncio.run(stackure.mcp(APP_ID)(app)({"type": "lifespan"}, None, None))
        self.assertEqual(seen, ["lifespan"])
        self.assertEqual(self.server.seen, [])

    def test_through_a_wsgi_server(self) -> None:
        def app(environ: dict[str, Any], start_response: Any) -> list[bytes]:
            user = stackure.user_from_request(environ)
            body = user.user_email.encode() if user else b""
            start_response("200 OK", [("Content-Length", str(len(body)))])
            return [body]

        front = wsgiref.simple_server.make_server(
            "127.0.0.1", 0, stackure.mcp(APP_ID)(app), handler_class=_Quiet
        )
        threading.Thread(target=front.serve_forever, args=(0.01,), daemon=True).start()
        self.addCleanup(front.server_close)
        self.addCleanup(front.shutdown)
        for sent, status, challenge, body in (
            ({"Cookie": f"stackure_session={TOKEN}"}, 401, CHALLENGE, b'{"error":"unauthorized"}'),
            ({"Authorization": f"Bearer {TOKEN}"}, 200, None, USER.user_email.encode()),
        ):
            with self.subTest(sent=sent), self.assertNoLogs("stackure", level="DEBUG"):
                self.server.seen = []
                conn = http.client.HTTPConnection("127.0.0.1", front.server_port, timeout=5)
                self.addCleanup(conn.close)
                conn.request("POST", "/mcp?session_id=1", headers=sent)
                resp = conn.getresponse()
                self.assertEqual((resp.status, resp.read()), (status, body))
                self.assertEqual(resp.getheader("WWW-Authenticate"), challenge)
                self.assertIsNone(resp.getheader("Set-Cookie"))
                self.assertIsNone(resp.getheader("Location"))
                self.assertEqual(self.mcp_url(), f"http://127.0.0.1:{front.server_port}/mcp")
