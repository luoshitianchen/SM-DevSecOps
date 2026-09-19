"""流水线管理路由。"""
from __future__ import annotations

from fastapi import APIRouter, Depends, Query, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_session
from app.schemas.pipeline import PipelineCreate, PipelineStatusUpdate, PipelineUpdate
from app.services.pipeline import PipelineService

router = APIRouter(prefix="/api/pipelines", tags=["pipelines"])


@router.get("")
async def list_pipelines(
    request: Request,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    status_filter: str | None = Query(default=None, alias="status"),
    keyword: str | None = Query(default=None),
    session: AsyncSession = Depends(get_session),
) -> dict:
    return await PipelineService.list_pipelines(session, limit=limit, offset=offset,
                                                status_filter=status_filter, keyword=keyword)


@router.post("", status_code=status.HTTP_201_CREATED)
async def create_pipeline(
    payload: PipelineCreate, request: Request,
    session: AsyncSession = Depends(get_session),
) -> dict:
    return await PipelineService.create_pipeline(session, payload, request)


@router.get("/{pipeline_id}")
async def get_pipeline(
    pipeline_id: str, request: Request,
    session: AsyncSession = Depends(get_session),
) -> dict:
    return await PipelineService.get_pipeline(session, pipeline_id)


@router.patch("/{pipeline_id}")
async def update_pipeline(
    pipeline_id: str, payload: PipelineUpdate, request: Request,
    session: AsyncSession = Depends(get_session),
) -> dict:
    return await PipelineService.update_pipeline(session, pipeline_id, payload, request)


@router.patch("/{pipeline_id}/status")
async def change_pipeline_status(
    pipeline_id: str, payload: PipelineStatusUpdate, request: Request,
    session: AsyncSession = Depends(get_session),
) -> dict:
    return await PipelineService.change_status(session, pipeline_id, payload, request)


@router.delete("/{pipeline_id}")
async def delete_pipeline(
    pipeline_id: str, request: Request,
    session: AsyncSession = Depends(get_session),
) -> dict:
    return await PipelineService.delete_pipeline(session, pipeline_id, request)
