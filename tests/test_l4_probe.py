import errno
import asyncio

import pytest
from unittest import mock

from probe.l4_probe import classify_errno, probe_host


def test_classify_errno():
    assert classify_errno(0) == "OPEN"
    assert classify_errno(errno.ECONNREFUSED) == "REFUSED"
    assert classify_errno(errno.ETIMEDOUT) == "FILTERED"
    assert classify_errno(999) == "ERR_999"


@pytest.mark.asyncio
async def test_probe_host_tcp_open(monkeypatch):
    async def fake_getaddrinfo(*_):
        return [(None, None, None, None, ("127.0.0.1", 80))]

    async def fake_tcp(*_, **__):
        return "OPEN"

    monkeypatch.setattr("probe.l4_probe.socket.create_connection",
                        lambda *_, **__: 0)
    monkeypatch.setattr("probe.l4_probe.asyncio.get_running_loop",
                        lambda: asyncio.get_event_loop())
    monkeypatch.setattr("probe.l4_probe.asyncio.AbstractEventLoop.getaddrinfo",
                        fake_getaddrinfo, raising=False)

    status = await probe_host("localhost", 80)
    assert status == "OPEN"
