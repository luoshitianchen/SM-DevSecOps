"""扫描结果管理路由。"""
from __future__ import annotations

from fastapi import APIRouter, Depends, Query, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_session
from app.schemas.scan_result import ScanCreate, ScanFail, ScanFinish
from app.services.scan_result import ScanService

router = APIRouter(prefix="/api/scans", tags=["scan-results"])


@router.get("")
async def list_scans(
    request: Request,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    status_filter: str | None = Query(default=None, alias="status"),
    pipeline_code: str | None = Query(default=None),
    scan_type: str | None = Query(default=None),
    session: AsyncSession = Depends(get_session),
) -> dict:
    return await ScanService.list_scans(session, limit=limit, offset=offset,
                                        status_filter=status_filter, pipeline_code=pipeline_code,
                                        scan_type=scan_type)


@router.post("", status_code=status.HTTP_201_CREATED)
async def create_scan(
    payload: ScanCreate, request: Request,
    session: AsyncSession = Depends(get_session),
) -> dict:
    return await ScanService.create_scan(session, payload, request)


@router.get("/{scan_id}")
async def get_scan(
    scan_id: str, request: Request,
    session: AsyncSession = Depends(get_session),
) -> dict:
    return await ScanService.get_scan(session, scan_id)


@router.post("/{scan_id}/start")
async def start_scan(
    scan_id: str, request: Request,
    session: AsyncSession = Depends(get_session),
) -> dict:
    return await ScanService.start_scan(session, scan_id, request)


@router.post("/{scan_id}/finish")
async def finish_scan(
    scan_id: str, payload: ScanFinish, request: Request,
    session: AsyncSession = Depends(get_session),
) -> dict:
    return await ScanService.finish_scan(session, scan_id, payload, request)


@router.post("/{scan_id}/fail")
async def fail_scan(
    scan_id: str, payload: ScanFail, request: Request,
    session: AsyncSession = Depends(get_session),
) -> dict:
    return await ScanService.fail_scan(session, scan_id, payload, request)
