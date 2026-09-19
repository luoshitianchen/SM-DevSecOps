"""流水线 Pydantic 模型。"""
from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field


class PipelineCreate(BaseModel):
    pipeline_code: str = Field(min_length=2, max_length=128, pattern=r"^[a-zA-Z0-9_.-]+$")
    name: str = Field(min_length=1, max_length=128)
    repo_url: str = Field(default="", max_length=512)
    triggers: list[str] = Field(default_factory=list)
    description: str = Field(default="", max_length=512)


class PipelineUpdate(BaseModel):
    name: str | None = Field(default=None, max_length=128)
    repo_url: str | None = Field(default=None, max_length=512)
    triggers: list[str] | None = None
    description: str | None = Field(default=None, max_length=512)


class PipelineStatusUpdate(BaseModel):
    status: str = Field(pattern=r"^(draft|active|disabled)$")


class PipelineResponse(BaseModel):
    id: str
    pipeline_code: str
    name: str
    repo_url: str
    status: str
    triggers: list[str]
    description: str
    created_at: datetime
    updated_at: datetime


class PipelineListResponse(BaseModel):
    total: int
    items: list[PipelineResponse]
