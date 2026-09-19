"""扫描结果仓储层。"""
from __future__ import annotations

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.scan_result import ScanResult


async def get_scan(session: AsyncSession, scan_id: str) -> ScanResult | None:
    result = await session.execute(select(ScanResult).where(ScanResult.id == scan_id))
    return result.scalar_one_or_none()


async def get_scan_by_scan_id(session: AsyncSession, scan_id: str) -> ScanResult | None:
    result = await session.execute(select(ScanResult).where(ScanResult.scan_id == scan_id))
    return result.scalar_one_or_none()


async def list_scans(
    session: AsyncSession, limit: int = 100, offset: int = 0,
    status: str | None = None, pipeline_code: str | None = None,
    scan_type: str | None = None,
) -> list[ScanResult]:
    stmt = select(ScanResult).order_by(ScanResult.created_at.desc()).limit(limit).offset(offset)
    if status:
        stmt = stmt.where(ScanResult.status == status)
    if pipeline_code:
        stmt = stmt.where(ScanResult.pipeline_code == pipeline_code)
    if scan_type:
        stmt = stmt.where(ScanResult.scan_type == scan_type)
    result = await session.execute(stmt)
    return list(result.scalars().all())


async def count_scans(
    session: AsyncSession, status: str | None = None,
    pipeline_code: str | None = None, scan_type: str | None = None,
) -> int:
    stmt = select(func.count(ScanResult.id))
    if status:
        stmt = stmt.where(ScanResult.status == status)
    if pipeline_code:
        stmt = stmt.where(ScanResult.pipeline_code == pipeline_code)
    if scan_type:
        stmt = stmt.where(ScanResult.scan_type == scan_type)
    result = await session.execute(stmt)
    return result.scalar_one()


async def create_scan(session: AsyncSession, scan: ScanResult) -> ScanResult:
    session.add(scan)
    await session.commit()
    await session.refresh(scan)
    return scan


async def update_scan(session: AsyncSession, scan: ScanResult) -> ScanResult:
    await session.commit()
    await session.refresh(scan)
    return scan
