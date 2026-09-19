"""SM-DevSecOps 业务深化测试：流水线/扫描/漏洞工单闭环。"""
from __future__ import annotations

import uuid

H = {"X-Internal-Token": "test-internal-key-12345"}
P = {"X-Internal-Token": "wrong-token"}


def _suffix() -> str:
    return uuid.uuid4().hex[:8]


async def _active_pipeline(client) -> dict:
    code = f"pl-{_suffix()}"
    create = await client.post("/api/pipelines", json={
        "pipeline_code": code, "name": f"流水线-{code}", "repo_url": "https://git.local/repo",
        "triggers": ["push"],
    }, headers=H)
    assert create.status_code == 201, create.text
    pid = create.json()["id"]
    act = await client.patch(f"/api/pipelines/{pid}/status", json={"status": "active"}, headers=H)
    assert act.status_code == 200, act.text
    return act.json()


async def _finished_scan(client, pipeline_code: str) -> dict:
    sid = f"scan-{_suffix()}"
    create = await client.post("/api/scans", json={
        "scan_id": sid, "pipeline_code": pipeline_code, "scan_type": "sast",
    }, headers=H)
    assert create.status_code == 201, create.text
    scan_id = create.json()["id"]
    await client.post(f"/api/scans/{scan_id}/start", headers=H)
    done = await client.post(f"/api/scans/{scan_id}/finish", json={
        "critical_count": 1, "high_count": 3, "summary": "发现4处问题",
    }, headers=H)
    assert done.status_code == 200, done.text
    return done.json()


# ═══════════════════════════════════════════════════════════
# 流水线
# ═══════════════════════════════════════════════════════════

class TestPipeline:
    async def test_create_pipeline_success(self, client):
        code = f"pl-{_suffix()}"
        resp = await client.post("/api/pipelines", json={
            "pipeline_code": code, "name": "创建测试", "repo_url": "https://git.local/x",
            "triggers": ["push", "tag"],
        }, headers=H)
        assert resp.status_code == 201
        data = resp.json()
        assert data["status"] == "draft"
        assert "push" in data["triggers"]

    async def test_create_pipeline_requires_token(self, client):
        resp = await client.post("/api/pipelines", json={
            "pipeline_code": f"pl-{_suffix()}", "name": "无令牌",
        }, headers=P)
        assert resp.status_code in (401, 403)

    async def test_create_pipeline_duplicate_code(self, client):
        code = f"pl-{_suffix()}"
        await client.post("/api/pipelines", json={"pipeline_code": code, "name": "一"}, headers=H)
        resp = await client.post("/api/pipelines", json={"pipeline_code": code, "name": "二"}, headers=H)
        assert resp.status_code == 409

    async def test_list_and_filter_pipelines(self, client):
        code = f"pl-{_suffix()}"
        await client.post("/api/pipelines", json={"pipeline_code": code, "name": "过滤"}, headers=H)
        resp = await client.get(f"/api/pipelines?status=draft&keyword={code}", headers=H)
        assert resp.status_code == 200
        assert any(p["pipeline_code"] == code for p in resp.json()["items"])

    async def test_get_pipeline_not_found(self, client):
        resp = await client.get("/api/pipelines/nope", headers=H)
        assert resp.status_code == 404

    async def test_update_pipeline(self, client):
        create = await client.post("/api/pipelines", json={"pipeline_code": f"pl-{_suffix()}", "name": "原名"}, headers=H)
        pid = create.json()["id"]
        resp = await client.patch(f"/api/pipelines/{pid}", json={"name": "新名", "description": "描述"}, headers=H)
        assert resp.status_code == 200
        assert resp.json()["name"] == "新名"

    async def test_status_transition_draft_to_active(self, client):
        create = await client.post("/api/pipelines", json={"pipeline_code": f"pl-{_suffix()}", "name": "启用"}, headers=H)
        pid = create.json()["id"]
        resp = await client.patch(f"/api/pipelines/{pid}/status", json={"status": "active"}, headers=H)
        assert resp.status_code == 200
        assert resp.json()["status"] == "active"

    async def test_illegal_status_transition(self, client):
        create = await client.post("/api/pipelines", json={"pipeline_code": f"pl-{_suffix()}", "name": "非法"}, headers=H)
        pid = create.json()["id"]
        resp = await client.patch(f"/api/pipelines/{pid}/status", json={"status": "disabled"}, headers=H)
        assert resp.status_code == 409

    async def test_delete_pipeline(self, client):
        create = await client.post("/api/pipelines", json={"pipeline_code": f"pl-{_suffix()}", "name": "删除"}, headers=H)
        pid = create.json()["id"]
        resp = await client.delete(f"/api/pipelines/{pid}", headers=H)
        assert resp.status_code == 200
        assert resp.json()["deleted"] is True


# ═══════════════════════════════════════════════════════════
# 扫描结果
# ═══════════════════════════════════════════════════════════

class TestScan:
    async def test_create_scan_requires_active_pipeline(self, client):
        code = f"pl-{_suffix()}"
        await client.post("/api/pipelines", json={"pipeline_code": code, "name": "草稿"}, headers=H)
        resp = await client.post("/api/scans", json={
            "scan_id": f"scan-{_suffix()}", "pipeline_code": code, "scan_type": "sast",
        }, headers=H)
        assert resp.status_code == 409

    async def test_create_scan_nonexistent_pipeline(self, client):
        resp = await client.post("/api/scans", json={
            "scan_id": f"scan-{_suffix()}", "pipeline_code": "ghost", "scan_type": "sast",
        }, headers=H)
        assert resp.status_code == 400

    async def test_create_scan_success(self, client):
        pl = await _active_pipeline(client)
        resp = await client.post("/api/scans", json={
            "scan_id": f"scan-{_suffix()}", "pipeline_code": pl["pipeline_code"], "scan_type": "secrets",
        }, headers=H)
        assert resp.status_code == 201
        assert resp.json()["status"] == "pending"
        assert resp.json()["scan_type"] == "secrets"

    async def test_scan_lifecycle_success(self, client):
        pl = await _active_pipeline(client)
        done = await _finished_scan(client, pl["pipeline_code"])
        assert done["status"] == "success"
        assert done["critical_count"] == 1
        assert done["high_count"] == 3
        assert done["finished_at"] is not None

    async def test_scan_fail_path(self, client):
        pl = await _active_pipeline(client)
        create = await client.post("/api/scans", json={
            "scan_id": f"scan-{_suffix()}", "pipeline_code": pl["pipeline_code"], "scan_type": "license",
        }, headers=H)
        sid = create.json()["id"]
        await client.post(f"/api/scans/{sid}/start", headers=H)
        resp = await client.post(f"/api/scans/{sid}/fail", json={"summary": "扫描器崩溃"}, headers=H)
        assert resp.status_code == 200
        assert resp.json()["status"] == "failed"

    async def test_illegal_scan_transition(self, client):
        pl = await _active_pipeline(client)
        create = await client.post("/api/scans", json={
            "scan_id": f"scan-{_suffix()}", "pipeline_code": pl["pipeline_code"], "scan_type": "sast",
        }, headers=H)
        sid = create.json()["id"]
        # pending 不能直接 finish
        resp = await client.post(f"/api/scans/{sid}/finish", json={"critical_count": 0}, headers=H)
        assert resp.status_code == 409

    async def test_list_scans_filter(self, client):
        pl = await _active_pipeline(client)
        await _finished_scan(client, pl["pipeline_code"])
        resp = await client.get(f"/api/scans?status=success&pipeline_code={pl['pipeline_code']}", headers=H)
        assert resp.status_code == 200
        assert resp.json()["total"] >= 1


# ═══════════════════════════════════════════════════════════
# 漏洞工单
# ═══════════════════════════════════════════════════════════

class TestTicket:
    async def test_create_ticket_success(self, client):
        pl = await _active_pipeline(client)
        scan = await _finished_scan(client, pl["pipeline_code"])
        resp = await client.post("/api/vuln-tickets", json={
            "ticket_no": f"vuln-{_suffix()}", "scan_id": scan["scan_id"], "vuln_id": "CVE-2026-0001",
            "severity": "critical", "title": "高危漏洞", "assignee": "alice",
        }, headers=H)
        assert resp.status_code == 201
        data = resp.json()
        assert data["status"] == "open"
        assert data["severity"] == "critical"

    async def test_create_ticket_nonexistent_scan(self, client):
        resp = await client.post("/api/vuln-tickets", json={
            "ticket_no": f"vuln-{_suffix()}", "scan_id": "ghost-scan", "vuln_id": "CVE-X",
            "severity": "high", "title": "幽灵",
        }, headers=H)
        assert resp.status_code == 400

    async def test_create_ticket_duplicate_no(self, client):
        pl = await _active_pipeline(client)
        scan = await _finished_scan(client, pl["pipeline_code"])
        no = f"vuln-{_suffix()}"
        await client.post("/api/vuln-tickets", json={
            "ticket_no": no, "scan_id": scan["scan_id"], "vuln_id": "CVE-A", "severity": "high", "title": "一",
        }, headers=H)
        resp = await client.post("/api/vuln-tickets", json={
            "ticket_no": no, "scan_id": scan["scan_id"], "vuln_id": "CVE-B", "severity": "high", "title": "二",
        }, headers=H)
        assert resp.status_code == 409

    async def test_ticket_closure_lifecycle(self, client):
        pl = await _active_pipeline(client)
        scan = await _finished_scan(client, pl["pipeline_code"])
        create = await client.post("/api/vuln-tickets", json={
            "ticket_no": f"vuln-{_suffix()}", "scan_id": scan["scan_id"], "vuln_id": "CVE-C",
            "severity": "high", "title": "闭环",
        }, headers=H)
        tid = create.json()["id"]
        s1 = await client.patch(f"/api/vuln-tickets/{tid}/status", json={"status": "in_progress"}, headers=H)
        assert s1.json()["status"] == "in_progress"
        s2 = await client.patch(f"/api/vuln-tickets/{tid}/status", json={"status": "fixed"}, headers=H)
        assert s2.json()["status"] == "fixed"
        s3 = await client.patch(f"/api/vuln-tickets/{tid}/status", json={"status": "closed"}, headers=H)
        assert s3.json()["status"] == "closed"

    async def test_illegal_ticket_transition(self, client):
        pl = await _active_pipeline(client)
        scan = await _finished_scan(client, pl["pipeline_code"])
        create = await client.post("/api/vuln-tickets", json={
            "ticket_no": f"vuln-{_suffix()}", "scan_id": scan["scan_id"], "vuln_id": "CVE-D",
            "severity": "medium", "title": "非法",
        }, headers=H)
        tid = create.json()["id"]
        # open 不能直接 closed
        resp = await client.patch(f"/api/vuln-tickets/{tid}/status", json={"status": "closed"}, headers=H)
        assert resp.status_code == 409

    async def test_assign_ticket(self, client):
        pl = await _active_pipeline(client)
        scan = await _finished_scan(client, pl["pipeline_code"])
        create = await client.post("/api/vuln-tickets", json={
            "ticket_no": f"vuln-{_suffix()}", "scan_id": scan["scan_id"], "vuln_id": "CVE-E",
            "severity": "low", "title": "指派",
        }, headers=H)
        tid = create.json()["id"]
        resp = await client.patch(f"/api/vuln-tickets/{tid}/assign", json={"assignee": "bob"}, headers=H)
        assert resp.status_code == 200
        assert resp.json()["assignee"] == "bob"

    async def test_list_and_search_tickets(self, client):
        pl = await _active_pipeline(client)
        scan = await _finished_scan(client, pl["pipeline_code"])
        await client.post("/api/vuln-tickets", json={
            "ticket_no": f"vuln-{_suffix()}", "scan_id": scan["scan_id"], "vuln_id": "CVE-SEARCH",
            "severity": "high", "title": "搜索目标漏洞",
        }, headers=H)
        resp = await client.get("/api/vuln-tickets?severity=high", headers=H)
        assert resp.status_code == 200
        assert resp.json()["total"] >= 1
        s = await client.get("/api/vuln-tickets/search?keyword=CVE-SEARCH", headers=H)
        assert s.status_code == 200
        assert any(t["vuln_id"] == "CVE-SEARCH" for t in s.json()["items"])
