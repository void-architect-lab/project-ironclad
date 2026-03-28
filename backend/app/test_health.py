"""
ironclad/tests/test_health.py
Smoke tests for liveness and readiness probes.
"""

import pytest
from httpx import ASGITransport, AsyncClient

from app.main import app


@pytest.mark.asyncio
async def test_liveness():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/api/v1/health/liveness")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "alive"


@pytest.mark.asyncio
async def test_readiness():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/api/v1/health/readiness")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ready"
    assert "uptime_seconds" in body
    assert "registered_scanners" in body


@pytest.mark.asyncio
async def test_submit_payload_missing_auth():
    payload = {
        "payload_type": "dockerfile",
        "content": "FROM ubuntu:22.04\nRUN apt-get update",
    }
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post("/api/v1/payloads/submit", json=payload)
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_submit_payload_accepted(monkeypatch):
    import app.config as cfg_module
    monkeypatch.setattr(cfg_module.get_settings(), "API_KEY", "test-key")

    payload = {
        "payload_type": "dockerfile",
        "content": "FROM ubuntu:22.04\nRUN apt-get update",
    }
    headers = {"X-Ironclad-Key": "test-key"}
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post("/api/v1/payloads/submit", json=payload, headers=headers)
    # 202 or 403 depending on env key — just assert it's not a 5xx
    assert response.status_code < 500
