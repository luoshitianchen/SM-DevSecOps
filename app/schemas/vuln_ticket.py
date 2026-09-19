"""漏洞工单 Pydantic 模型。"""
from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field


class TicketCreate(BaseModel):
    ticket_no: str = Field(min_length=2, max_length=128, pattern=r"^[a-zA-Z0-9_.-]+$")
    scan_id: str = Field(min_length=1, max_length=128)
    vuln_id: str = Field(min_length=1, max_length=128)
    severity: Literal["critical", "high", "medium", "low"]
    title: str = Field(min_length=1, max_length=256)
    assignee: str = Field(default="", max_length=128)
    description: str = Field(default="", max_length=8192)


class TicketAssign(BaseModel):
    assignee: str = Field(min_length=1, max_length=128)


class TicketStatusUpdate(BaseModel):
    status: str = Field(pattern=r"^(open|in_progress|fixed|closed)$")


class TicketResponse(BaseModel):
    id: str
    ticket_no: str
    scan_id: str
    vuln_id: str
    severity: str
    title: str
    status: str
    assignee: str
    description: str
    created_at: datetime
    updated_at: datetime


class TicketListResponse(BaseModel):
    total: int
    items: list[TicketResponse]
