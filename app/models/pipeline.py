"""流水线定义模型。"""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, String, Text
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.sql import func

from app.models.base import Base


class Pipeline(Base):
    """流水线定义：CI/CD 安全流水线的元数据。"""

    __tablename__ = "pipelines"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    pipeline_code: Mapped[str] = mapped_column(String(128), nullable=False, unique=True, index=True)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    repo_url: Mapped[str] = mapped_column(String(512), default="")
    # 状态机：draft(草稿) -> active(启用) -> disabled(停用)
    status: Mapped[str] = mapped_column(String(16), default="draft", index=True)
    # 触发条件，JSON 数组字符串
    triggers: Mapped[str] = mapped_column(Text, default="[]")
    description: Mapped[str] = mapped_column(String(512), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
