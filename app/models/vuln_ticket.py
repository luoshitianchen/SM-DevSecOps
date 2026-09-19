"""漏洞工单模型。"""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, String, Text
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.sql import func

from app.models.base import Base


class VulnTicket(Base):
    """漏洞工单：扫描发现的漏洞闭环管理。"""

    __tablename__ = "vuln_tickets"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    ticket_no: Mapped[str] = mapped_column(String(128), nullable=False, unique=True, index=True)
    # 来源扫描（逻辑外键）
    scan_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    vuln_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    # 严重级别：critical / high / medium / low
    severity: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(256), nullable=False)
    # 状态机：open -> in_progress -> fixed -> closed
    status: Mapped[str] = mapped_column(String(16), default="open", index=True)
    assignee: Mapped[str] = mapped_column(String(128), default="")
    description: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
