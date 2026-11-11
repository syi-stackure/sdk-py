"""Closed organizations: the ``org.closed`` events Stackure queues for the app."""

import asyncio
import concurrent.futures
import contextlib
import inspect
import logging
import os
import sys
import threading
from collections.abc import Callable, Coroutine
from typing import Any

from . import client
from .config import EVENTS_PATH, LOOP_CHECK_S, MAX_EVENTS, app_id
from .errors import StackureError

_logger = logging.getLogger(__name__)

type _OrgClosed = Callable[[str], object]

_org_closed: _OrgClosed | None = None
_loop: asyncio.AbstractEventLoop | None = None
_draining = threading.Lock()
_warned = threading.Lock()


def on_org_closed[F: Callable[[str], object]](fn: F) -> F:
    """Register the function that deletes what the app stores for a closed organization.

    ``fn`` gets the closed organization's ``account_id``, the same value as
    ``User.account_id``. The SDK checks once now, and Stackure reports new
    closures on the session checks the SDK already makes. The SDK runs ``fn``
    in a background thread, once for each closed organization, and tells
    Stackure each one is done when ``fn`` returns.

    An ``async`` function runs on the app's event loop when there is one: the
    loop serving the latest request through :func:`auth` or :func:`mcp`, or
    before that the loop ``on_org_closed`` was called from. Registered with
    no running loop, such as at import, it waits for the first session
    check. With no loop serving requests, it runs in that thread with
    :func:`asyncio.run`.

    The same organization can arrive again, so ``fn`` must also succeed when
    there is nothing left to delete. When it raises, or the app's event loop
    stops before it finishes, the SDK logs it and tries that organization
    again on a later check, at least 5 minutes later.

    Registering again replaces the earlier function. Never raises. Returns
    ``fn``, so it also works as a decorator.

    Example:
        >>> @on_org_closed
        ... def delete_org(account_id):
        ...     db.delete_org(account_id)
    """
    global _org_closed
    _org_closed = fn
    note_loop()
    if _loop is not None or not inspect.iscoroutinefunction(fn):
        _drain_events()
    return fn


def note_loop() -> None:
    """Keep the running event loop, if there is one, for ``async`` functions."""
    global _loop
    with contextlib.suppress(RuntimeError):
        _loop = asyncio.get_running_loop()


def note_events(waiting: int) -> None:
    """Act on the ``events_waiting`` count from a session check. Never raises."""
    if waiting <= 0:
        return
    if _org_closed is None:
        if _warned.acquire(blocking=False):
            _logger.warning(
                "stackure: %s waiting for this app to delete their data. "
                "Register stackure.on_org_closed to delete it.",
                _closed_orgs(waiting),
            )
        return
    _drain_events()


def _closed_orgs(n: int) -> str:
    return "1 closed organization is" if n == 1 else f"{n} closed organizations are"


def _drain_events() -> None:
    fn = _org_closed
    if fn is None or not _draining.acquire(blocking=False):
        return
    try:
        threading.Thread(target=_drain, args=(fn,), name="stackure-events", daemon=True).start()
    except Exception as exc:
        _draining.release()
        _log_failure(exc)


def _drain(fn: _OrgClosed) -> None:
    try:
        _process_events(fn)
    except Exception as exc:
        _log_failure(exc)
    finally:
        _draining.release()


def _log_failure(exc: Exception) -> None:
    _logger.error("stackure: closed organizations not deleted yet: %s", exc)


def _process_events(fn: _OrgClosed) -> None:
    ack: list[str] = []
    while True:
        events, more = _take_events(ack, MAX_EVENTS)
        ack = []
        err: Exception | None = None
        for event_id, kind, account_id in events:
            if kind != "org.closed":
                continue
            try:
                _run_org_closed(fn, account_id)
            except Exception as exc:
                err = exc
                break
            ack.append(event_id)
        if err is None and more:
            continue
        if ack:
            try:
                _take_events(ack, 0)
            except Exception as exc:
                err = err or exc
        if err is not None:
            raise err
        return


def _run_org_closed(fn: _OrgClosed, account_id: str) -> None:
    try:
        result = fn(account_id)
        if inspect.iscoroutine(result):
            _await(result)
    except (Exception, asyncio.CancelledError) as exc:
        raise RuntimeError(f"deleting organization {account_id}: {exc}") from exc


def _await(coro: Coroutine[Any, Any, object]) -> None:
    """Run ``coro`` on the app's event loop while it runs, else with :func:`asyncio.run`."""
    loop = _loop
    if loop is None or not loop.is_running():
        asyncio.run(coro)
        return
    future = asyncio.run_coroutine_threadsafe(coro, loop)
    while loop.is_running() and not future.done():
        concurrent.futures.wait([future], LOOP_CHECK_S)
    if future.cancelled():
        raise RuntimeError("cancelled on the app's event loop")
    if not future.done():
        raise RuntimeError("the app's event loop stopped")
    future.result()


def _take_events(ack: list[str], max_events: int) -> tuple[list[tuple[str, str, str]], bool]:
    """Acknowledge ``ack`` and claim up to ``max_events`` more of the app's events.

    Returns each claimed event's ID, type and account ID, and whether more
    are waiting.

    Raises:
        StackureError: On invalid input, or any transport or API failure.
    """
    data = client._request(
        "POST",
        EVENTS_PATH,
        body={"app_id": app_id(), "ack": ack or None, "max_events": max_events},
    )
    try:
        events = [
            (e["id"], e["type"], (e.get("data") or {}).get("account_id", ""))
            for e in data.get("events") or ()
        ]
        return events, data.get("more") is True
    except (AttributeError, KeyError, TypeError) as exc:
        raise StackureError("network", "unexpected API response format") from exc


def _after_fork() -> None:
    global _draining, _loop
    _draining = threading.Lock()
    _loop = None


if sys.platform != "win32":
    os.register_at_fork(after_in_child=_after_fork)
