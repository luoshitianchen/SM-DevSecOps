"""流水线仓储层。"""
from __future__ import annotations

from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.pipeline import Pipeline


async def get_pipeline(session: AsyncSession, pipeline_id: str) -> Pipeline | None:
    result = await session.execute(select(Pipeline).where(Pipeline.id == pipeline_id))
    return result.scalar_one_or_none()


async def get_pipeline_by_code(session: AsyncSession, pipeline_code: str) -> Pipeline | None:
    result = await session.execute(select(Pipeline).where(Pipeline.pipeline_code == pipeline_code))
    return result.scalar_one_or_none()


async def list_pipelines(
    session: AsyncSession, limit: int = 100, offset: int = 0,
    status: str | None = None, keyword: str | None = None,
) -> list[Pipeline]:
    stmt = select(Pipeline).order_by(Pipeline.created_at.desc()).limit(limit).offset(offset)
    if status:
        stmt = stmt.where(Pipeline.status == status)
    if keyword:
        like = f"%{keyword}%"
        stmt = stmt.where(or_(Pipeline.name.like(like), Pipeline.pipeline_code.like(like)))
    result = await session.execute(stmt)
    return list(result.scalars().all())


async def count_pipelines(
    session: AsyncSession, status: str | None = None, keyword: str | None = None,
) -> int:
    stmt = select(func.count(Pipeline.id))
    if status:
        stmt = stmt.where(Pipeline.status == status)
    if keyword:
        like = f"%{keyword}%"
        stmt = stmt.where(or_(Pipeline.name.like(like), Pipeline.pipeline_code.like(like)))
    result = await session.execute(stmt)
    return result.scalar_one()


async def create_pipeline(session: AsyncSession, pipeline: Pipeline) -> Pipeline:
    session.add(pipeline)
    await session.commit()
    await session.refresh(pipeline)
    return pipeline


async def update_pipeline(session: AsyncSession, pipeline: Pipeline) -> Pipeline:
    await session.commit()
    await session.refresh(pipeline)
    return pipeline


async def delete_pipeline(session: AsyncSession, pipeline: Pipeline) -> None:
    await session.delete(pipeline)
    await session.commit()
