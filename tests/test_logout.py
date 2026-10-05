"""Tests for :func:`stackure.logout` against a local stand-in for Stackure."""

import http.client
import http.server
import os
import threading
import time
import unittest
import wsgiref.simple_server
from typing import Any
from unittest import mock

import stackure
from stackure import client

TOKEN = "0b9f6c1e-3a7d-4c58-9e21-6d4f8a2b7c10"
APP_ID = "7f3c1a2e-9b4d-4e6f-8a1b-2c3d4e5f6071"
SECRET = "app-secret-under-test"
SESSION = f"theme=dark; stackure_session={TOKEN}"
HOST = "app.example.com"
ORIGIN = f"https://{HOST}"
SIGN_OUT = ("POST", "/api/public/auth/sign-out")
SIGNED_OUT = (200, {"Content-Type": "application/json"}, b'{"message": "signed out"}')
CLEARED = ("Set-Cookie", "stackure_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0")
CLEARED_SECURE = (
    "Set-Cookie",
    "stackure_session=; Path=/; HttpOnly; SameSite=Lax; Secure; Max-Age=0",
)
FAILED = "ERROR:stackure.middleware:stackure: sign-out failed: "


class _Handler(http.server.BaseHTTPRequestHandler):
    def do_POST(self) -> None:
        server: Any = self.server
        server.seen.append((self.command, self.path, self.headers))
        time.sleep(server.delay)
        status, headers, body = server.reply
        self.send_response(status)
        for name, value in headers.items():
            self.send_header(name, value)
        self.end_headers()
        time.sleep(server.stall)
        self.wfile.write(body)

    do_GET = do_POST

    def log_message(self, format: str, *args: Any) -> None:
        pass


class _Server(http.server.ThreadingHTTPServer):
    def handle_error(self, request: Any, client_address: Any) -> None:
        pass


class _Quiet(wsgiref.simple_server.WSGIRequestHandler):
    def log_message(self, format: str, *args: Any) -> None:
        pass


class LogoutTest(unittest.TestCase):
    def setUp(self) -> None:
        self.server: Any = _Server(("127.0.0.1", 0), _Handler)
        self.server.seen, self.server.delay, self.server.stall = [], 0, 0
        self.server.reply = SIGNED_OUT
        threading.Thread(target=self.server.serve_forever, args=(0.01,), daemon=True).start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.base = f"http://127.0.0.1:{self.server.server_port}"
        env = mock.patch.dict(os.environ, {"STACKURE_BASE_URL": self.base})
        env.start()
        self.addCleanup(env.stop)
        os.environ.pop("STACKURE_APP_SECRET", None)
        os.environ.pop("STACKURE_APP_ID", None)

    def logout(
        self,
        cookie: str | None = SESSION,
        method: str = "POST",
        site: str | None = "same-origin",
        origin: str | None = None,
        host: str | None = HOST,
        scheme: str = "http",
        proto: str | None = None,
        twice: str = "",
        asgi: bool = False,
    ) -> stackure.Redirect:
        lines = [
            (name, value)
            for name, value in (
                ("host", host),
                ("sec-fetch-site", site),
                ("origin", origin),
                ("cookie", cookie),
                ("x-forwarded-proto", proto),
                ("user-agent", "browser/1"),
            )
            if value is not None
            for _ in range(1 + (name == twice))
        ]
        if asgi:
            return stackure.logout(
                {
                    "type": "http",
                    "method": method,
                    "scheme": scheme,
                    "client": ("203.0.113.7", 50000),
                    "headers": [(name.encode(), value.encode()) for name, value in lines],
                }
            )
        environ = {
            "REQUEST_METHOD": method,
            "wsgi.url_scheme": scheme,
            "REMOTE_ADDR": "203.0.113.7",
        }
        for name, value in lines:
            key = "HTTP_" + name.upper().replace("-", "_")
            environ[key] = f"{environ[key]},{value}" if key in environ else value
        return stackure.logout(environ)

    def acted(self, path: str, cleared: tuple[str, str] = CLEARED) -> stackure.Redirect:
        return stackure.Redirect(303, [("Location", self.base + path), cleared])

    def declined(self) -> stackure.Redirect:
        return stackure.Redirect(303, [("Location", self.base + "/signout")])

    def requests(self) -> list[tuple[str, str]]:
        return [(method, path) for method, path, _ in self.server.seen]

    def test_same_origin_post_signs_out_with_bearer_and_no_app_secret(self) -> None:
        with mock.patch.dict(
            os.environ, {"STACKURE_APP_SECRET": SECRET, "STACKURE_APP_ID": APP_ID}
        ):
            for asgi in (False, True):
                with self.subTest(asgi=asgi), self.assertNoLogs(level="DEBUG"):
                    self.server.seen = []
                    self.assertEqual(self.logout(asgi=asgi), self.acted("/"))
                    [(method, path, headers)] = self.server.seen
                    self.assertEqual((method, path), SIGN_OUT)
                    self.assertEqual(headers["Authorization"], f"Bearer {TOKEN}")
                    self.assertEqual(headers["Content-Length"], "0")
                    self.assertEqual(headers["User-Agent"], "browser/1")
                    self.assertEqual(headers["X-Forwarded-For"], "203.0.113.7")
                    self.assertIsNone(headers["Cookie"])
                    self.assertIsNone(headers["X-App-Secret"])
                    self.assertNotIn(SECRET, str(headers))
            client.validate_token(TOKEN, stackure.Request())
        self.assertEqual(self.server.seen[-1][2]["X-App-Secret"], SECRET)

    def test_asgi_cookie_split_over_header_lines_is_read(self) -> None:
        scope = {
            "type": "http",
            "method": "POST",
            "headers": [
                (b"sec-fetch-site", b"same-origin"),
                (b"cookie", f"stackure_session={TOKEN}".encode()),
                (b"cookie", b"theme=dark"),
            ],
        }
        with self.assertNoLogs(level="DEBUG"):
            self.assertEqual(stackure.logout(scope), self.acted("/"))
        [(_, _, headers)] = self.server.seen
        self.assertEqual(headers["Authorization"], f"Bearer {TOKEN}")

    def test_no_token_sends_no_request(self) -> None:
        for cookie in (None, "", "theme=dark", "session=" + TOKEN):
            with self.subTest(cookie=cookie), self.assertNoLogs(level="DEBUG"):
                self.assertEqual(self.logout(cookie), self.acted("/"))
        self.assertEqual(self.server.seen, [])

    def test_malformed_token_sends_no_request(self) -> None:
        for token in ("abc", TOKEN[:-1], TOKEN + "0", TOKEN.replace("-4c58-", "-1c58-")):
            with self.subTest(token=token), self.assertNoLogs(level="DEBUG"):
                self.assertEqual(self.logout(f"stackure_session={token}"), self.acted("/"))
        self.assertEqual(self.server.seen, [])

    def test_token_with_newline_is_never_logged_or_sent(self) -> None:
        for token in (
            f"{TOKEN}\nx",
            f"{TOKEN}\n x",
            f"{TOKEN}\r\nX-Injected: 1",
            f"{TOKEN[:18]}\n{TOKEN[18:]}",
            f"x\n{TOKEN}",
        ):
            with self.subTest(token=token), self.assertNoLogs(level="DEBUG"):
                self.assertEqual(self.logout(f"stackure_session={token}"), self.acted("/"))
                client.sign_out(token, stackure.Request())
        self.assertEqual(self.server.seen, [])

    def test_token_followed_by_bare_newline_is_never_sent(self) -> None:
        for token in (f"{TOKEN}\n", f"{TOKEN}\r", f"{TOKEN}\r\n", f"\n{TOKEN}"):
            with self.subTest(token=token), self.assertNoLogs(level="DEBUG"):
                client.sign_out(token, stackure.Request())
        self.assertEqual(self.server.seen, [])
        client.sign_out(TOKEN, stackure.Request())
        self.assertEqual(self.requests(), [SIGN_OUT])

    def test_any_2xx_is_success_whatever_the_body(self) -> None:
        for reply in (
            (200, {"Content-Length": "0"}, b""),
            (200, {}, b""),
            (204, {}, b""),
            (202, {"Content-Length": "8"}, b"not json"),
            (200, {"Content-Length": "64"}, b""),
        ):
            with self.subTest(reply=reply), self.assertNoLogs(level="DEBUG"):
                self.server.seen, self.server.reply = [], reply
                self.assertEqual(self.logout(), self.acted("/"))
                self.assertEqual(self.requests(), [SIGN_OUT])

    def test_2xx_with_body_cut_short_is_success_and_called_once(self) -> None:
        self.server.reply = (200, {"Content-Length": "64"}, b'{"message": "sig')
        with self.assertNoLogs(level="DEBUG"):
            self.assertEqual(self.logout(), self.acted("/"))
        self.assertEqual(self.requests(), [SIGN_OUT])

    def test_2xx_does_not_wait_for_the_body(self) -> None:
        self.server.stall = 1
        self.server.reply = (200, {"Content-Length": "25"}, SIGNED_OUT[2])
        with mock.patch.object(client, "_REQUEST_TIMEOUT_S", 0.3):
            with self.assertNoLogs(level="DEBUG"):
                self.assertEqual(self.logout(), self.acted("/"))
        self.assertEqual(self.requests(), [SIGN_OUT])

    def test_api_failure_redirects_to_signout(self) -> None:
        for status, code in ((401, "auth"), (403, "forbidden"), (404, "network"), (500, "network")):
            with self.subTest(status=status):
                self.server.seen, self.server.reply = [], (status, {}, TOKEN.encode())
                with self.assertLogs(level="DEBUG") as logs:
                    result = self.logout()
                self.assertEqual(result, self.acted("/signout"))
                self.assertEqual(logs.output, [FAILED + code])
                self.assertEqual(set(self.requests()), {SIGN_OUT})

    def test_redirect_is_a_failure_and_is_not_followed(self) -> None:
        for status in (302, 307):
            with self.subTest(status=status):
                self.server.seen = []
                self.server.reply = (status, {"Location": self.base + "/elsewhere"}, b"")
                with self.assertLogs(level="DEBUG") as logs:
                    result = self.logout()
                self.assertEqual(result, self.acted("/signout"))
                self.assertEqual(logs.output, [FAILED + "network"])
                self.assertEqual(self.requests(), [SIGN_OUT])

    def test_network_failure_redirects_to_signout(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        with self.assertLogs(level="DEBUG") as logs:
            result = self.logout()
        self.assertEqual(result, self.acted("/signout"))
        self.assertEqual(logs.output, [FAILED + "network"])
        self.assertEqual(self.server.seen, [])

    def test_timeout_redirects_to_signout(self) -> None:
        self.server.delay = 1
        with mock.patch.object(client, "_REQUEST_TIMEOUT_S", 0.2):
            with self.assertLogs(level="DEBUG") as logs:
                result = self.logout()
        self.assertEqual(result, self.acted("/signout"))
        self.assertEqual(logs.output, [FAILED + "timeout"])

    def test_get_does_not_act(self) -> None:
        for asgi in (False, True):
            for method in ("GET", "HEAD"):
                with self.subTest(asgi=asgi, method=method), self.assertNoLogs(level="DEBUG"):
                    result = self.logout(method=method, origin=ORIGIN, asgi=asgi)
                    self.assertEqual(result, self.declined())
        self.assertEqual(self.server.seen, [])

    def test_cross_site_post_does_not_act(self) -> None:
        for asgi in (False, True):
            for site in ("cross-site", "same-site", "none", "Same-Origin", "same-origin-x"):
                with self.subTest(asgi=asgi, site=site), self.assertNoLogs(level="DEBUG"):
                    result = self.logout(site=site, origin=ORIGIN, asgi=asgi)
                    self.assertEqual(result, self.declined())
        self.assertEqual(self.server.seen, [])

    def test_sec_fetch_site_present_decides_alone(self) -> None:
        for asgi in (False, True):
            with self.subTest(asgi=asgi), self.assertNoLogs(level="DEBUG"):
                self.server.seen = []
                self.assertEqual(self.logout(site="", origin=ORIGIN, asgi=asgi), self.declined())
                self.assertEqual(self.server.seen, [])
                self.assertEqual(self.logout(site=None, origin=ORIGIN, asgi=asgi), self.acted("/"))
                self.assertEqual(self.requests(), [SIGN_OUT])
                result = self.logout(origin="https://evil.example", asgi=asgi)
                self.assertEqual(result, self.acted("/"))
                self.assertEqual(self.requests(), [SIGN_OUT, SIGN_OUT])

    def test_repeated_header_does_not_act(self) -> None:
        for asgi in (False, True):
            for site, twice in (
                ("same-origin", "host"),
                ("same-origin", "sec-fetch-site"),
                ("same-origin", "origin"),
                (None, "host"),
                (None, "origin"),
            ):
                with self.subTest(asgi=asgi, site=site, twice=twice):
                    with self.assertNoLogs(level="DEBUG"):
                        result = self.logout(site=site, origin=ORIGIN, twice=twice, asgi=asgi)
                        self.assertEqual(result, self.declined())
        with self.assertNoLogs(level="DEBUG"):
            self.assertEqual(self.logout(host=f"{HOST}, {HOST}"), self.declined())
            self.assertEqual(self.logout(origin=f"{ORIGIN}, {ORIGIN}"), self.declined())
        self.assertEqual(self.server.seen, [])

    def test_header_lines_through_a_wsgi_server(self) -> None:
        def app(environ: dict[str, Any], start_response: Any) -> list[bytes]:
            r = stackure.logout(environ)
            start_response(f"{r.status} See Other", r.headers)
            return [b""]

        front = wsgiref.simple_server.make_server("127.0.0.1", 0, app, handler_class=_Quiet)
        threading.Thread(target=front.serve_forever, args=(0.01,), daemon=True).start()
        self.addCleanup(front.server_close)
        self.addCleanup(front.shutdown)
        same = (("Host", HOST), ("Sec-Fetch-Site", "same-origin"), ("Origin", ORIGIN))
        for lines, acts in (
            (same, True),
            *(((*same, line), False) for line in same),
            ((("Host", HOST), ("Sec-Fetch-Site", ""), ("Origin", ORIGIN)), False),
        ):
            with self.subTest(lines=lines), self.assertNoLogs(level="DEBUG"):
                self.server.seen = []
                conn = http.client.HTTPConnection("127.0.0.1", front.server_port, timeout=5)
                self.addCleanup(conn.close)
                conn.putrequest("POST", "/logout", skip_host=True, skip_accept_encoding=True)
                for name, value in (*lines, ("Cookie", SESSION), ("Content-Length", "0")):
                    conn.putheader(name, value)
                conn.endheaders()
                resp = conn.getresponse()
                resp.read()
                sent = [(k, v) for k, v in resp.getheaders() if k in ("Location", "Set-Cookie")]
                self.assertEqual(
                    stackure.Redirect(resp.status, sent),
                    self.acted("/") if acts else self.declined(),
                )
                self.assertEqual(self.requests(), [SIGN_OUT] if acts else [])

    def test_post_with_matching_origin_acts(self) -> None:
        for asgi in (False, True):
            for origin, host in (
                (ORIGIN, HOST),
                (f"http://{HOST}", HOST),
                ("https://APP.Example.com", "app.example.COM"),
                ("http://localhost:8000", "localhost:8000"),
                ("http://[::1]:8000", "[::1]:8000"),
            ):
                with self.subTest(asgi=asgi, origin=origin, host=host):
                    with self.assertNoLogs(level="DEBUG"):
                        self.server.seen = []
                        result = self.logout(site=None, origin=origin, host=host, asgi=asgi)
                        self.assertEqual(result, self.acted("/"))
                        self.assertEqual(self.requests(), [SIGN_OUT])

    def test_origin_scheme_must_be_https_on_an_https_request(self) -> None:
        for asgi in (False, True):
            for scheme, proto in (("https", None), ("http", "https")):
                with self.subTest(asgi=asgi, scheme=scheme, proto=proto):
                    with self.assertNoLogs(level="DEBUG"):
                        self.server.seen = []
                        result = self.logout(
                            site=None,
                            origin=f"http://{HOST}",
                            scheme=scheme,
                            proto=proto,
                            asgi=asgi,
                        )
                        self.assertEqual(result, self.declined())
                        self.assertEqual(self.server.seen, [])
                        result = self.logout(
                            site=None, origin=ORIGIN, scheme=scheme, proto=proto, asgi=asgi
                        )
                        self.assertEqual(result, self.acted("/", CLEARED_SECURE))
                        self.assertEqual(self.requests(), [SIGN_OUT])

    def test_post_with_non_matching_origin_does_not_act(self) -> None:
        for asgi in (False, True):
            for origin, host in (
                ("https://evil.example", HOST),
                (f"https://{HOST}.evil.example", HOST),
                (f"https://{HOST}evil.example", HOST),
                (f"https://evil{HOST}", HOST),
                (f"https://evil.{HOST}", HOST),
                (f"https://{HOST[:-1]}", HOST),
                (f"https://{HOST[1:]}", HOST),
                ("https://example.com", HOST),
                (f"https://evil.example/{HOST}", HOST),
                (f"https://{HOST}@evil.example", HOST),
                (f"https://{HOST}:8443", HOST),
                (ORIGIN, f"{HOST}:8443"),
                (HOST, HOST),
                ("null", HOST),
                ("null", ""),
                ("https://", ""),
            ):
                with self.subTest(asgi=asgi, origin=origin, host=host):
                    with self.assertNoLogs(level="DEBUG"):
                        result = self.logout(site=None, origin=origin, host=host, asgi=asgi)
                        self.assertEqual(result, self.declined())
        self.assertEqual(self.server.seen, [])

    def test_post_without_fetch_metadata_or_origin_does_not_act(self) -> None:
        for asgi in (False, True):
            for origin in (None, ""):
                with self.subTest(asgi=asgi, origin=origin), self.assertNoLogs(level="DEBUG"):
                    result = self.logout(site=None, origin=origin, asgi=asgi)
                    self.assertEqual(result, self.declined())
        self.assertEqual(self.server.seen, [])

    def test_unreadable_request_does_not_raise(self) -> None:
        with self.assertLogs(level="DEBUG") as logs:
            result = stackure.logout(object())
        self.assertEqual(result, self.declined())
        self.assertEqual(logs.output, [FAILED + "TypeError"])
        self.assertEqual(self.server.seen, [])
