"""扫描结果模型。"""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.sql import func

from app.models.base import Base


class ScanResult(Base):
    """扫描结果：一次流水线安全扫描的产出。"""

    __tablename__ = "scan_results"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    scan_id: Mapped[str] = mapped_column(String(128), nullable=False, unique=True, index=True)
    # 归属流水线编码（逻辑外键）
    pipeline_code: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    # 扫描类型：sast / dsca / secrets / license
    scan_type: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    # 状态机：pending -> running -> success | failed
    status: Mapped[str] = mapped_column(String(16), default="pending", index=True)
    critical_count: Mapped[int] = mapped_column(Integer, default=0)
    high_count: Mapped[int] = mapped_column(Integer, default=0)
    medium_count: Mapped[int] = mapped_column(Integer, default=0)
    low_count: Mapped[int] = mapped_column(Integer, default=0)
    summary: Mapped[str] = mapped_column(Text, default="")
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
