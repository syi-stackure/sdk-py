"""Tests for identity facts and :func:`stackure.directory` against a local stand-in for Stackure."""

import dataclasses
import http.server
import json
import os
import threading
import unittest
from typing import Any
from unittest import mock

import stackure

TOKEN = "0b9f6c1e-3a7d-4c58-9e21-6d4f8a2b7c10"
APP_ID = "7f3c1a2e-9b4d-4e6f-8a1b-2c3d4e5f6071"
SECRET = "app-secret-under-test"
ADA = {
    "user_id": "3c9a7e52-6b1d-4f08-a2c4-8e5d1f7b9a63",
    "user_email": "ada@example.com",
    "user_first_name": "Ada",
    "user_last_name": "Lovelace",
}
USER = {**ADA, "account_id": "a1f4c8d2-7e3b-4956-8d0a-2b6c9e4f1d37"}
OPS = {"team_id": "4b5c6d7e-8f9a-4b1c-8d2e-3f4a5b6c7d8e", "team_name": "Ops"}
DIRECTORY = f"/api/public/directory?app_id={APP_ID}"


class _Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        server: Any = self.server
        server.seen.append((self.path, self.headers))
        status, body = server.reply
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: Any) -> None:
        pass


class _Server(http.server.ThreadingHTTPServer):
    def handle_error(self, request: Any, client_address: Any) -> None:
        pass


def _environ(**headers: str) -> dict[str, Any]:
    environ = {
        "REQUEST_METHOD": "GET",
        "PATH_INFO": "/share",
        "REMOTE_ADDR": "203.0.113.7",
        "HTTP_HOST": "app.example.com",
        "HTTP_USER_AGENT": "browser/1",
    }
    environ.update({"HTTP_" + name.upper(): value for name, value in headers.items()})
    return environ


def _scope(**headers: str) -> dict[str, Any]:
    return {
        "type": "http",
        "method": "GET",
        "path": "/share",
        "client": ("203.0.113.7", 50000),
        "headers": [
            (name.encode(), value.encode())
            for name, value in {"user-agent": "browser/1", **headers}.items()
        ],
    }


class DirectoryTest(unittest.TestCase):
    def setUp(self) -> None:
        self.server: Any = _Server(("127.0.0.1", 0), _Handler)
        self.server.seen, self.server.reply = [], (200, b"{}")
        threading.Thread(target=self.server.serve_forever, args=(0.01,), daemon=True).start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        env = mock.patch.dict(
            os.environ,
            {
                "STACKURE_BASE_URL": f"http://127.0.0.1:{self.server.server_port}",
                "STACKURE_APP_SECRET": SECRET,
                "STACKURE_APP_ID": APP_ID,
            },
        )
        env.start()
        self.addCleanup(env.stop)

    def mcp_user(self) -> stackure.User | None:
        users: list[stackure.User | None] = []

        def app(environ: dict[str, Any], start_response: Any) -> list[bytes]:
            users.append(stackure.user_from_request(environ))
            start_response("200 OK", [])
            return [b""]

        stackure.mcp()(app)(_environ(authorization=f"Bearer {TOKEN}"), lambda *a: None)
        return users[0] if users else None

    def test_identity_facts_are_decoded_for_session_and_mcp_users(self) -> None:
        ada = stackure.User(**USER)
        admin = dataclasses.replace(ada, user_is_app_admin=True, user_teams=(stackure.Team(**OPS),))
        for user, want in (
            ({**USER, "user_is_app_admin": True, "user_teams": [OPS]}, admin),
            ({**USER, "user_is_app_admin": False, "user_teams": []}, ada),
            (USER, ada),
        ):
            with self.subTest(user=user):
                self.server.reply = (
                    200,
                    json.dumps({"authenticated": True, "user": user}).encode(),
                )
                result = stackure.verify(_environ(cookie=f"stackure_session={TOKEN}"))
                self.assertEqual(result.user, want)
                self.assertEqual(self.mcp_user(), want)

    def test_directory_lists_users_and_teams(self) -> None:
        self.server.reply = (200, json.dumps({"users": [ADA], "teams": [OPS]}).encode())
        want = stackure.Directory(
            users=(stackure.DirectoryUser(**ADA),), teams=(stackure.Team(**OPS),)
        )
        cookie = f"theme=dark; stackure_session={TOKEN}"
        for request in (_environ(cookie=cookie), _scope(cookie=cookie)):
            with self.subTest(request=request):
                self.server.seen = []
                self.assertEqual(stackure.directory(request), want)
                [(path, headers)] = self.server.seen
                self.assertEqual(path, DIRECTORY)
                self.assertEqual(headers["X-App-Secret"], SECRET)
                self.assertEqual(headers["Cookie"], f"session={TOKEN}")
                self.assertIsNone(headers["Authorization"])
                self.assertEqual(headers["User-Agent"], "browser/1")
                self.assertEqual(headers["X-Forwarded-For"], "203.0.113.7")

    def test_directory_errors(self) -> None:
        for status, body, code, calls in (
            (401, b'{"error":"invalid session"}', "auth", 1),
            (401, b'{"error":"invalid app secret"}', "auth", 1),
            (400, b'{"error":"invalid app_id format"}', "network", 1),
            (429, b'{"error":"rate limited"}', "network", 1),
            (500, b'{"error":"internal"}', "network", 2),
            (200, b'{"users":[{"user_id":"x"}],"teams":[]}', "network", 1),
        ):
            with self.subTest(status=status, body=body):
                self.server.seen, self.server.reply = [], (status, body)
                with self.assertRaises(stackure.StackureError) as caught:
                    stackure.directory(_environ(cookie=f"stackure_session={TOKEN}"))
                self.assertEqual(caught.exception.code, code)
                if status == 401:
                    self.assertEqual(caught.exception.message, body.decode())
                    self.assertEqual(caught.exception.status_code, 401)
                self.assertEqual([path for path, _ in self.server.seen], [DIRECTORY] * calls)

    def test_directory_without_a_session_is_auth_without_a_call(self) -> None:
        for headers in (
            {},
            {"cookie": "stackure_session=not-a-token"},
            {"cookie": f"session={TOKEN}"},
            {"authorization": f"Bearer {TOKEN}"},
        ):
            with self.subTest(headers=headers):
                with self.assertRaises(stackure.StackureError) as caught:
                    stackure.directory(_environ(**headers))
                self.assertEqual(
                    (caught.exception.code, caught.exception.message, caught.exception.status_code),
                    ("auth", "invalid session", None),
                )
        self.assertEqual(self.server.seen, [])

    def test_directory_without_an_app_secret_is_validation(self) -> None:
        with mock.patch.dict(os.environ):
            del os.environ["STACKURE_APP_SECRET"]
            with self.assertRaises(stackure.StackureError) as caught:
                stackure.directory(_environ(cookie=f"stackure_session={TOKEN}"))
        self.assertEqual(caught.exception.code, "validation")
        self.assertEqual(self.server.seen, [])
