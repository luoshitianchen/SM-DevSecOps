"""SM DevSecOps 领域测试：扫描、漏洞闭环、策略与 SBOM。"""

import pytest
from fastapi.testclient import TestClient

from app import base
from app.main import VERSION, app


@pytest.fixture()
def client(monkeypatch):
    monkeypatch.setattr(base, "internal_api_key", lambda: "TEST")
    base.reset_state()
    from app.main import _init as init_db
    init_db()
    with TestClient(app) as c:
        c.headers["X-Internal-Token"] = "TEST"
        yield c


def test_health_and_version(client):
    r = client.get("/health", headers={"X-Request-Id": "suite-test"})
    assert r.status_code == 200
    assert r.json()["version"] == VERSION


def test_scan_and_findings(client):
    scan = client.post("/api/devsecops/scans", json={"name": "secret-scan", "target": "repo/app", "scan_type": "secret", "sample_findings": 5}).json()
    assert scan["status"] == "completed"
    assert scan["findings"] == 5
    assert sum(scan["severity_counts"].values()) == 5
    detail = client.get(f"/api/devsecops/scans/{scan['id']}").json()
    assert len(detail["findings"]) == 5
    assert client.get("/api/devsecops/findings", params={"severity": "critical"}).json()["total"] >= 0


def test_finding_triage(client):
    scan = client.post("/api/devsecops/scans", json={"name": "code-scan", "target": "repo/app", "scan_type": "code", "sample_findings": 2}).json()
    finding_id = client.get(f"/api/devsecops/scans/{scan['id']}").json()["findings"][0]["id"]
    assert client.post(f"/api/devsecops/findings/{finding_id}/triage", json={"status": "fixed", "note": "已修复"}).json()["status"] == "fixed"
    assert client.get("/api/devsecops/findings", params={"status_": "fixed"}).json()["total"] == 1
    assert client.post("/api/devsecops/findings/nope/triage", json={"status": "fixed"}).status_code == 404


def test_policy(client):
    assert client.post("/api/devsecops/policies", json={"name": "block-critical", "rule": "severity == critical", "action": "block"}).status_code == 201
    assert client.post("/api/devsecops/policies", json={"name": "block-critical", "rule": "block", "action": "block"}).status_code == 409
    assert client.get("/api/devsecops/policies").json()["total"] == 1


def test_sbom(client):
    scan = client.post("/api/devsecops/scans", json={"name": "dep-scan", "target": "svc", "scan_type": "dependency", "sample_findings": 0}).json()
    sbom = client.post(f"/api/devsecops/scans/{scan['id']}/sbom").json()
    assert sbom["format"] == "cyclonedx"
    assert client.post("/api/devsecops/scans/nope/sbom").status_code == 404


def test_stats(client):
    client.post("/api/devsecops/scans", json={"name": "s1", "target": "repo", "scan_type": "code", "sample_findings": 3})
    stats = client.get("/api/devsecops/stats").json()
    assert stats["scans"] == 1
    assert stats["findings_open"] == 3


def test_manifest_and_crypto(client):
    assert client.get("/api/integration/manifest").json()["version"] == VERSION
    enc = client.post("/api/crypto/encrypt", json={"value": "x"}).json()["ciphertext"]
    assert client.post("/api/crypto/decrypt", json={"value": enc}).json()["plaintext"] == "x"


def test_write_requires_auth(client):
    del client.headers["X-Internal-Token"]
    assert client.post("/api/devsecops/scans", json={"name": "x", "target": "t", "scan_type": "code"}).status_code == 401
