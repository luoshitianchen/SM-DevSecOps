"""流水线服务层：定义与状态机管理。"""
from __future__ import annotations

import json
import uuid

from fastapi import HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import internal_write_allowed
from app.models.pipeline import Pipeline
from app.repositories import pipeline as repo
from app.schemas.pipeline import PipelineCreate, PipelineStatusUpdate, PipelineUpdate
from app.services.audit import record_audit

# 流水线合法状态迁移表
_TRANSITIONS: dict[str, set[str]] = {
    "draft": {"active"},
    "active": {"disabled"},
    "disabled": {"active"},
}


def _pipeline_to_dict(p: Pipeline) -> dict:
    return {
        "id": p.id, "pipeline_code": p.pipeline_code, "name": p.name,
        "repo_url": p.repo_url or "", "status": p.status,
        "triggers": json.loads(p.triggers or "[]"),
        "description": p.description or "",
        "created_at": p.created_at.isoformat() if p.created_at else "",
        "updated_at": p.updated_at.isoformat() if p.updated_at else "",
    }


class PipelineService:
    @staticmethod
    async def list_pipelines(session, limit, offset, status_filter, keyword) -> dict:
        items = await repo.list_pipelines(session, limit=limit, offset=offset,
                                          status=status_filter, keyword=keyword)
        total = await repo.count_pipelines(session, status=status_filter, keyword=keyword)
        return {"total": total, "items": [_pipeline_to_dict(p) for p in items]}

    @staticmethod
    async def get_pipeline(session: AsyncSession, pipeline_id: str) -> dict:
        item = await repo.get_pipeline(session, pipeline_id)
        if not item:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "流水线不存在")
        return _pipeline_to_dict(item)

    @staticmethod
    async def create_pipeline(session: AsyncSession, payload: PipelineCreate, request: Request) -> dict:
        if not internal_write_allowed(request):
            raise HTTPException(status.HTTP_403_FORBIDDEN, "内部写入令牌无效")
        if await repo.get_pipeline_by_code(session, payload.pipeline_code):
            raise HTTPException(status.HTTP_409_CONFLICT, "流水线编码已存在")
        item = Pipeline(
            id=str(uuid.uuid4()), pipeline_code=payload.pipeline_code, name=payload.name,
            repo_url=payload.repo_url, triggers=json.dumps(payload.triggers, ensure_ascii=False),
            description=payload.description, status="draft",
        )
        item = await repo.create_pipeline(session, item)
        await record_audit(session, "pipeline.created", "internal",
                           f"pipeline_code={payload.pipeline_code}", request)
        return _pipeline_to_dict(item)

    @staticmethod
    async def update_pipeline(session: AsyncSession, pipeline_id: str, payload: PipelineUpdate,
                              request: Request) -> dict:
        if not internal_write_allowed(request):
            raise HTTPException(status.HTTP_403_FORBIDDEN, "内部写入令牌无效")
        item = await repo.get_pipeline(session, pipeline_id)
        if not item:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "流水线不存在")
        if payload.name is not None:
            item.name = payload.name
        if payload.repo_url is not None:
            item.repo_url = payload.repo_url
        if payload.triggers is not None:
            item.triggers = json.dumps(payload.triggers, ensure_ascii=False)
        if payload.description is not None:
            item.description = payload.description
        item = await repo.update_pipeline(session, item)
        await record_audit(session, "pipeline.updated", "internal", f"pipeline_id={pipeline_id}", request)
        return _pipeline_to_dict(item)

    @staticmethod
    async def change_status(session: AsyncSession, pipeline_id: str, payload: PipelineStatusUpdate,
                            request: Request) -> dict:
        if not internal_write_allowed(request):
            raise HTTPException(status.HTTP_403_FORBIDDEN, "内部写入令牌无效")
        item = await repo.get_pipeline(session, pipeline_id)
        if not item:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "流水线不存在")
        new_status = payload.status
        if new_status == item.status:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "目标状态与当前状态一致")
        if new_status not in _TRANSITIONS.get(item.status, set()):
            raise HTTPException(status.HTTP_409_CONFLICT,
                                f"非法状态迁移: {item.status} -> {new_status}")
        item.status = new_status
        item = await repo.update_pipeline(session, item)
        await record_audit(session, "pipeline.status_changed", "internal",
                           f"pipeline_code={item.pipeline_code} status={new_status}", request)
        return _pipeline_to_dict(item)

    @staticmethod
    async def delete_pipeline(session: AsyncSession, pipeline_id: str, request: Request) -> dict:
        if not internal_write_allowed(request):
            raise HTTPException(status.HTTP_403_FORBIDDEN, "内部写入令牌无效")
        item = await repo.get_pipeline(session, pipeline_id)
        if not item:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "流水线不存在")
        code = item.pipeline_code
        await repo.delete_pipeline(session, item)
        await record_audit(session, "pipeline.deleted", "internal", f"pipeline_code={code}", request)
        return {"deleted": True, "id": pipeline_id}
