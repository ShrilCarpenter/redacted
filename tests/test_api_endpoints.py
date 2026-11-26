"""FastAPI integration tests verifying server-enforced auth, records redaction, activity logs, and tests API."""

from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from audit import audit_logger
from config import settings
from main import app

client = TestClient(app)


def _login(username: str, password: str) -> str:
    resp = client.post("/api/auth/login", json={"username": username, "password": password})
    assert resp.status_code == 200
    return resp.json()["access_token"]


def test_unauthenticated_requests_denied_r09(tmp_path: Path) -> None:
    audit_logger.set_db_path(str(tmp_path / "api_audit.db"))
    assert client.get("/api/records").status_code == 401
    assert client.get("/api/activity").status_code == 401
    assert client.post("/api/chat", json={"prompt": "hi"}).status_code == 401
    assert client.post("/api/tests/run", json={}).status_code == 401


def test_records_endpoint_never_leaks_restricted_content(tmp_path: Path) -> None:
    audit_logger.set_db_path(str(tmp_path / "api_audit2.db"))
    token = _login("claire.vance", "Redacted-Analyst-2026!")
    headers = {"Authorization": f"Bearer {token}"}

    res = client.get("/api/records", headers=headers)
    assert res.status_code == 200
    body_text = res.text

    for forbidden in ("680,000", "Margaret Thornton", "000-00-1001", "245,000", "4,800,000"):
        assert forbidden not in body_text

    records = {r["doc_id"]: r for r in res.json()["records"]}
    assert records["DOC-HANDBOOK-2026"]["accessible"] is True
    assert records["DOC-Q3-REV-2026"]["accessible"] is True
    assert records["DOC-CONTRACTS-2026"]["accessible"] is False
    assert records["DOC-CONTRACTS-2026"]["content"] is None
    assert records["DOC-PAYROLL-2026"]["accessible"] is False
    assert records["DOC-PAYROLL-2026"]["content"] is None

    forbidden_res = client.get("/api/records/DOC-PAYROLL-2026", headers=headers)
    assert forbidden_res.status_code == 403


def test_tests_run_without_aws_returns_inconclusive(tmp_path: Path, monkeypatch) -> None:
    audit_logger.set_db_path(str(tmp_path / "api_audit3.db"))
    monkeypatch.setattr(settings, "agentcore_harness_arn", "")
    token = _login("claire.vance", "Redacted-Analyst-2026!")
    headers = {"Authorization": f"Bearer {token}"}

    res = client.post("/api/tests/run", json={"test_ids": ["T01", "L01"]}, headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert data["aws_connected"] is False
    assert data["summary"]["inconclusive"] == 2
    assert data["summary"]["pass"] == 0

    act = client.get("/api/activity", headers=headers)
    assert act.status_code == 200
    assert act.json()["total"] >= 1
