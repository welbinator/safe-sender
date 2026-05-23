"""F-16: POST /customers/test-connection must not block on SMTP.

These tests exercise CustomerService.start_test_smtp_connection / get_test_connection_status
directly (no HTTP layer needed) and stub out the SMTP-sending worker so the
event loop never touches a real socket. The bug the audit caught:
the old POST handler awaited the full SMTP send + a 10s poll synchronously,
so any concurrent request shared the same single-worker uvicorn slot.
"""
import asyncio
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


@pytest.fixture(autouse=True)
def _reset_jobs():
    from services import customers as svc_mod
    svc_mod._test_jobs.clear()
    yield
    svc_mod._test_jobs.clear()


@pytest.mark.asyncio
async def test_start_returns_immediately_and_polling_finds_result(monkeypatch):
    from services.customers import CustomerService, TestConnectionResult

    svc = CustomerService(customers=None, scan_logs=object())

    # Stub the actual SMTP worker — keep it slow enough that without
    # backgrounding, the start call would obviously block.
    async def fake_run(*args, **kwargs):
        await asyncio.sleep(0.2)
        return TestConnectionResult(True, "ok")

    monkeypatch.setattr(svc, "_run_test_smtp_connection", fake_run)

    customer = {"id": "cust_42"}
    loop = asyncio.get_event_loop()
    t0 = loop.time()
    test_id = await svc.start_test_smtp_connection(
        customer,
        smtp_host="h",
        smtp_port=587,
        auth_username="",
        auth_password="",
    )
    elapsed = loop.time() - t0
    # Start must return fast — well under the 0.2s SMTP stub.
    assert elapsed < 0.1
    assert test_id

    # Initially pending.
    status = await svc.get_test_connection_status(test_id, "cust_42")
    assert status == {"status": "pending"}

    # Wait for worker.
    await asyncio.sleep(0.35)
    status = await svc.get_test_connection_status(test_id, "cust_42")
    assert status == {"status": "done", "success": True, "message": "ok"}


@pytest.mark.asyncio
async def test_polling_with_wrong_customer_returns_none(monkeypatch):
    from services.customers import CustomerService, TestConnectionResult

    svc = CustomerService(customers=None, scan_logs=object())

    async def fake_run(*args, **kwargs):
        return TestConnectionResult(True, "ok")

    monkeypatch.setattr(svc, "_run_test_smtp_connection", fake_run)

    test_id = await svc.start_test_smtp_connection(
        {"id": "cust_owner"},
        smtp_host="h",
        smtp_port=587,
        auth_username="",
        auth_password="",
    )
    # Cross-tenant lookup must be opaque.
    assert await svc.get_test_connection_status(test_id, "cust_other") is None


@pytest.mark.asyncio
async def test_polling_unknown_id_returns_none():
    from services.customers import CustomerService

    svc = CustomerService(customers=None, scan_logs=object())
    assert await svc.get_test_connection_status("nope", "cust_x") is None


@pytest.mark.asyncio
async def test_worker_exception_surfaces_as_failure(monkeypatch):
    from services.customers import CustomerService

    svc = CustomerService(customers=None, scan_logs=object())

    async def boom(*args, **kwargs):
        raise RuntimeError("DNS blew up")

    monkeypatch.setattr(svc, "_run_test_smtp_connection", boom)

    test_id = await svc.start_test_smtp_connection(
        {"id": "cust_42"},
        smtp_host="h",
        smtp_port=587,
        auth_username="",
        auth_password="",
    )
    await asyncio.sleep(0.05)
    status = await svc.get_test_connection_status(test_id, "cust_42")
    assert status["status"] == "done"
    assert status["success"] is False
    assert "DNS blew up" in status["message"]
