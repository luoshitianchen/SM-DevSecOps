"""扫描结果 Pydantic 模型。"""
from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field


class ScanCreate(BaseModel):
    scan_id: str = Field(min_length=2, max_length=128, pattern=r"^[a-zA-Z0-9_.-]+$")
    pipeline_code: str = Field(min_length=1, max_length=128)
    scan_type: Literal["sast", "dsca", "secrets", "license"]


class ScanFinish(BaseModel):
    critical_count: int = Field(default=0, ge=0)
    high_count: int = Field(default=0, ge=0)
    medium_count: int = Field(default=0, ge=0)
    low_count: int = Field(default=0, ge=0)
    summary: str = Field(default="", max_length=8192)


class ScanFail(BaseModel):
    summary: str = Field(default="", max_length=8192)


class ScanResponse(BaseModel):
    id: str
    scan_id: str
    pipeline_code: str
    scan_type: str
    status: str
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    summary: str
    started_at: datetime | None = None
    finished_at: datetime | None = None
    created_at: datetime


class ScanListResponse(BaseModel):
    total: int
    items: list[ScanResponse]
