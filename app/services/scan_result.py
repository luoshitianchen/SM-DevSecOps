"""扫描结果服务层：扫描执行状态机。"""
from __future__ import annotations

import uuid
from datetime import UTC, datetime

from fastapi import HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import internal_write_allowed
from app.models.scan_result import ScanResult
from app.repositories import pipeline as pipeline_repo
from app.repositories import scan_result as repo
from app.schemas.scan_result import ScanCreate, ScanFail, ScanFinish
from app.services.audit import record_audit

# 扫描合法状态迁移表
_TRANSITIONS: dict[str, set[str]] = {
    "pending": {"running"},
    "running": {"success", "failed"},
    "success": set(),
    "failed": set(),
}


def _scan_to_dict(s: ScanResult) -> dict:
    return {
        "id": s.id, "scan_id": s.scan_id, "pipeline_code": s.pipeline_code,
        "scan_type": s.scan_type, "status": s.status,
        "critical_count": s.critical_count, "high_count": s.high_count,
        "medium_count": s.medium_count, "low_count": s.low_count,
        "summary": s.summary or "",
        "started_at": s.started_at.isoformat() if s.started_at else None,
        "finished_at": s.finished_at.isoformat() if s.finished_at else None,
        "created_at": s.created_at.isoformat() if s.created_at else "",
    }


def _guard(current: str, new_status: str) -> None:
    if new_status == current:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "目标状态与当前状态一致")
    if new_status not in _TRANSITIONS.get(current, set()):
        raise HTTPException(status.HTTP_409_CONFLICT, f"非法状态迁移: {current} -> {new_status}")


class ScanService:
    @staticmethod
    async def list_scans(session, limit, offset, status_filter, pipeline_code, scan_type) -> dict:
        items = await repo.list_scans(session, limit=limit, offset=offset, status=status_filter,
                                      pipeline_code=pipeline_code, scan_type=scan_type)
        total = await repo.count_scans(session, status=status_filter, pipeline_code=pipeline_code,
                                       scan_type=scan_type)
        return {"total": total, "items": [_scan_to_dict(s) for s in items]}

    @staticmethod
    async def get_scan(session: AsyncSession, scan_id: str) -> dict:
        item = await repo.get_scan(session, scan_id)
        if not item:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "扫描记录不存在")
        return _scan_to_dict(item)

    @staticmethod
    async def create_scan(session: AsyncSession, payload: ScanCreate, request: Request) -> dict:
        if not internal_write_allowed(request):
            raise HTTPException(status.HTTP_403_FORBIDDEN, "内部写入令牌无效")
        pipeline = await pipeline_repo.get_pipeline_by_code(session, payload.pipeline_code)
        if not pipeline:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "归属流水线不存在")
        if pipeline.status != "active":
            raise HTTPException(status.HTTP_409_CONFLICT, "流水线未启用，无法触发扫描")
        if await repo.get_scan_by_scan_id(session, payload.scan_id):
            raise HTTPException(status.HTTP_409_CONFLICT, "扫描编号已存在")
        item = ScanResult(
            id=str(uuid.uuid4()), scan_id=payload.scan_id, pipeline_code=payload.pipeline_code,
            scan_type=payload.scan_type, status="pending",
        )
        item = await repo.create_scan(session, item)
        await record_audit(session, "scan.created", "internal",
                           f"scan_id={payload.scan_id} pipeline={payload.pipeline_code}", request)
        return _scan_to_dict(item)

    @staticmethod
    async def start_scan(session: AsyncSession, scan_id: str, request: Request) -> dict:
        if not internal_write_allowed(request):
            raise HTTPException(status.HTTP_403_FORBIDDEN, "内部写入令牌无效")
        item = await repo.get_scan(session, scan_id)
        if not item:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "扫描记录不存在")
        _guard(item.status, "running")
        item.status = "running"
        item.started_at = datetime.now(UTC)
        item = await repo.update_scan(session, item)
        await record_audit(session, "scan.started", "internal", f"scan_id={item.scan_id}", request)
        return _scan_to_dict(item)

    @staticmethod
    async def finish_scan(session: AsyncSession, scan_id: str, payload: ScanFinish,
                          request: Request) -> dict:
        if not internal_write_allowed(request):
            raise HTTPException(status.HTTP_403_FORBIDDEN, "内部写入令牌无效")
        item = await repo.get_scan(session, scan_id)
        if not item:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "扫描记录不存在")
        _guard(item.status, "success")
        item.status = "success"
        item.critical_count = payload.critical_count
        item.high_count = payload.high_count
        item.medium_count = payload.medium_count
        item.low_count = payload.low_count
        item.summary = payload.summary
        item.finished_at = datetime.now(UTC)
        item = await repo.update_scan(session, item)
        await record_audit(session, "scan.finished", "internal", f"scan_id={item.scan_id}", request)
        return _scan_to_dict(item)

    @staticmethod
    async def fail_scan(session: AsyncSession, scan_id: str, payload: ScanFail,
                        request: Request) -> dict:
        if not internal_write_allowed(request):
            raise HTTPException(status.HTTP_403_FORBIDDEN, "内部写入令牌无效")
        item = await repo.get_scan(session, scan_id)
        if not item:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "扫描记录不存在")
        _guard(item.status, "failed")
        item.status = "failed"
        item.summary = payload.summary
        item.finished_at = datetime.now(UTC)
        item = await repo.update_scan(session, item)
        await record_audit(session, "scan.failed", "internal", f"scan_id={item.scan_id}", request)
        return _scan_to_dict(item)
