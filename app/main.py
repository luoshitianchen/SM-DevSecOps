"""SM DevSecOps —— 安全研发平台：扫描任务、漏洞闭环、安全策略与 SBOM。"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from typing import Any

from fastapi import HTTPException, Request, status
from pydantic import BaseModel, Field

from app import base

SERVICE = "sm-devsecops"
VERSION = "3.0.0"
NAME = "SM DevSecOps"
DESCRIPTION = "安全研发平台：扫描任务、漏洞闭环、安全策略与 SBOM"
PORT = 8340


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _init() -> None:
    with base.db_ctx() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id TEXT PRIMARY KEY, name TEXT NOT NULL, target TEXT NOT NULL,
                scan_type TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'running',
                severity_counts TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL, finished_at TEXT
            );
            CREATE TABLE IF NOT EXISTS findings (
                id TEXT PRIMARY KEY, scan_id TEXT NOT NULL, severity TEXT NOT NULL,
                rule TEXT NOT NULL, file TEXT, description TEXT, status TEXT NOT NULL DEFAULT 'open',
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS policies (
                id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE, rule TEXT NOT NULL,
                action TEXT NOT NULL DEFAULT 'warn', enabled INTEGER NOT NULL DEFAULT 1
            );
            CREATE TABLE IF NOT EXISTS sboms (
                id TEXT PRIMARY KEY, scan_id TEXT NOT NULL, format TEXT NOT NULL DEFAULT 'cyclonedx',
                content TEXT NOT NULL, created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity, status);
            """
        )


app = base.create_app(
    service=SERVICE, name=NAME, description=DESCRIPTION, version=VERSION, port=PORT,
    dependencies=["sm-iam", "sm-event-bus", "sm-audit-log-center"],
    events=["scan.completed", "finding.triaged", "policy.blocked"],
    overview_fn=lambda _r: {
        "summary": {
            "scans": base.get_db().execute("SELECT COUNT(*) FROM scans").fetchone()[0],
            "open_findings": base.get_db().execute("SELECT COUNT(*) FROM findings WHERE status='open'").fetchone()[0],
        }
    },
)
_init()


class ScanIn(BaseModel):
    name: str = Field(min_length=2, max_length=80)
    target: str = Field(min_length=2, max_length=300)
    scan_type: str = Field(pattern=r"^(secret|dependency|code|image)$")
    sample_findings: int = Field(default=3, ge=0, le=20)


class PolicyIn(BaseModel):
    name: str = Field(min_length=2, max_length=80)
    rule: str = Field(min_length=2, max_length=200)
    action: str = Field(default="warn", pattern=r"^(block|warn)$")


class FindingTriageIn(BaseModel):
    status: str = Field(pattern=r"^(triaged|fixed|accepted)$")
    note: str = Field(default="", max_length=300)


_RULES = {
    "secret": [("hardcoded-secret", "检测到硬编码密钥/口令"), ("aws-credential", "检测到 AWS 凭据"), ("private-key", "检测到私钥片段")],
    "dependency": [("CVE-2026-0001", "依赖存在已知高危漏洞"), ("CVE-2026-0002", "依赖版本过期"), ("CVSS-9.1", "依赖存在严重漏洞")],
    "code": [("injection-sqli", "存在 SQL 注入风险"), ("xss-reflected", "存在反射型 XSS 风险"), ("insecure-deserialization", "不安全的反序列化")],
    "image": [("image-root-user", "镜像以 root 运行"), ("image-outdated-base", "基础镜像过旧"), ("image-non-pinned", "镜像标签未固定摘要")],
}


@app.post("/api/devsecops/scans", status_code=status.HTTP_201_CREATED)
def create_and_run_scan(payload: ScanIn, request: Request) -> dict[str, Any]:
    base.require_internal_token(request)
    scan_id = str(uuid.uuid4())
    severity_cycle = ["critical", "high", "medium", "low"]
    counts: dict[str, int] = {}
    with base.db_ctx() as conn:
        conn.execute("INSERT INTO scans (id, name, target, scan_type, status, severity_counts, created_at, finished_at) VALUES (?,?,?,?,?,?,?,?)", (scan_id, payload.name, payload.target, payload.scan_type, "completed", "{}", _now(), _now()))
        rules = _RULES.get(payload.scan_type, _RULES["code"])
        for i in range(payload.sample_findings):
            rule, desc = rules[i % len(rules)]
            severity = severity_cycle[i % len(severity_cycle)]
            finding_id = str(uuid.uuid4())
            conn.execute("INSERT INTO findings (id, scan_id, severity, rule, file, description, status, created_at) VALUES (?,?,?,?,?,?,?,?)", (finding_id, scan_id, severity, rule, f"src/app/{payload.scan_type}/sample_{i}.py", desc, "open", _now()))
            counts[severity] = counts.get(severity, 0) + 1
        conn.execute("UPDATE scans SET severity_counts=? WHERE id=?", (json.dumps(counts, ensure_ascii=False), scan_id))
        base.record_audit("scan.completed", "internal", f"scan={scan_id} type={payload.scan_type} findings={payload.sample_findings}", getattr(request.state, "request_id", ""), getattr(request.state, "trace_id", ""), SERVICE)
    return {"id": scan_id, "name": payload.name, "status": "completed", "severity_counts": counts, "findings": payload.sample_findings}


@app.get("/api/devsecops/scans")
def list_scans() -> dict[str, Any]:
    with base.db_ctx() as conn:
        rows = conn.execute("SELECT * FROM scans ORDER BY created_at DESC").fetchall()
    return {"items": [dict(r) for r in rows], "total": len(rows)}


@app.get("/api/devsecops/scans/{scan_id}")
def get_scan(scan_id: str) -> dict[str, Any]:
    with base.db_ctx() as conn:
        scan = conn.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
        if not scan:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "扫描任务不存在")
        findings = conn.execute("SELECT * FROM findings WHERE scan_id=?", (scan_id,)).fetchall()
    return {**dict(scan), "findings": [dict(r) for r in findings]}


@app.get("/api/devsecops/findings")
def list_findings(severity: str | None = None, status_: str | None = None) -> dict[str, Any]:
    clauses, params = [], []
    if severity:
        clauses.append("severity=?")
        params.append(severity)
    if status_:
        clauses.append("status=?")
        params.append(status_)
    where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
    with base.db_ctx() as conn:
        rows = conn.execute(f"SELECT * FROM findings{where} ORDER BY created_at DESC LIMIT 200", params).fetchall()
    return {"items": [dict(r) for r in rows], "total": len(rows)}


@app.post("/api/devsecops/findings/{finding_id}/triage")
def triage_finding(finding_id: str, payload: FindingTriageIn, request: Request) -> dict[str, Any]:
    base.require_internal_token(request)
    with base.db_ctx() as conn:
        if conn.execute("UPDATE findings SET status=? WHERE id=?", (payload.status, finding_id)).rowcount == 0:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "漏洞记录不存在")
        base.record_audit("finding.triaged", "internal", f"finding={finding_id} status={payload.status}", getattr(request.state, "request_id", ""), getattr(request.state, "trace_id", ""), SERVICE)
    return {"id": finding_id, "status": payload.status}


@app.post("/api/devsecops/policies", status_code=status.HTTP_201_CREATED)
def create_policy(payload: PolicyIn, request: Request) -> dict[str, Any]:
    base.require_internal_token(request)
    policy_id = str(uuid.uuid4())
    with base.db_ctx() as conn:
        try:
            conn.execute("INSERT INTO policies VALUES (?,?,?,?,1)", (policy_id, payload.name, payload.rule, payload.action))
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(status.HTTP_409_CONFLICT, "策略已存在") from exc
    return {"id": policy_id, "name": payload.name}


@app.get("/api/devsecops/policies")
def list_policies() -> dict[str, Any]:
    with base.db_ctx() as conn:
        rows = conn.execute("SELECT * FROM policies").fetchall()
    return {"items": [dict(r) for r in rows], "total": len(rows)}


@app.post("/api/devsecops/scans/{scan_id}/sbom", status_code=status.HTTP_201_CREATED)
def create_sbom(scan_id: str, request: Request) -> dict[str, Any]:
    base.require_internal_token(request)
    with base.db_ctx() as conn:
        scan = conn.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
        if not scan:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "扫描任务不存在")
        sbom_id = str(uuid.uuid4())
        content = json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.5", "serialNumber": f"urn:uuid:{sbom_id}", "metadata": {"component": {"name": scan["target"], "type": "application"}}}, ensure_ascii=False)
        conn.execute("INSERT INTO sboms VALUES (?,?,?,?,?)", (sbom_id, scan_id, "cyclonedx", content, _now()))
    return {"id": sbom_id, "scan_id": scan_id, "format": "cyclonedx"}


@app.get("/api/devsecops/stats")
def stats() -> dict[str, Any]:
    with base.db_ctx() as conn:
        def _count(sql: str) -> int:
            return conn.execute(sql).fetchone()[0]
        return {
            "scans": _count("SELECT COUNT(*) FROM scans"),
            "findings_open": _count("SELECT COUNT(*) FROM findings WHERE status='open'"),
            "findings_fixed": _count("SELECT COUNT(*) FROM findings WHERE status='fixed'"),
            "critical": _count("SELECT COUNT(*) FROM findings WHERE severity='critical' AND status='open'"),
            "high": _count("SELECT COUNT(*) FROM findings WHERE severity='high' AND status='open'"),
            "blocking_policies": _count("SELECT COUNT(*) FROM policies WHERE action='block' AND enabled=1"),
        }