"""漏洞工单仓储层。"""
from __future__ import annotations

from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.vuln_ticket import VulnTicket


async def get_ticket(session: AsyncSession, ticket_id: str) -> VulnTicket | None:
    result = await session.execute(select(VulnTicket).where(VulnTicket.id == ticket_id))
    return result.scalar_one_or_none()


async def get_ticket_by_no(session: AsyncSession, ticket_no: str) -> VulnTicket | None:
    result = await session.execute(select(VulnTicket).where(VulnTicket.ticket_no == ticket_no))
    return result.scalar_one_or_none()


async def list_tickets(
    session: AsyncSession, limit: int = 100, offset: int = 0,
    status: str | None = None, severity: str | None = None,
    scan_id: str | None = None, assignee: str | None = None,
) -> list[VulnTicket]:
    stmt = select(VulnTicket).order_by(VulnTicket.created_at.desc()).limit(limit).offset(offset)
    if status:
        stmt = stmt.where(VulnTicket.status == status)
    if severity:
        stmt = stmt.where(VulnTicket.severity == severity)
    if scan_id:
        stmt = stmt.where(VulnTicket.scan_id == scan_id)
    if assignee:
        stmt = stmt.where(VulnTicket.assignee == assignee)
    result = await session.execute(stmt)
    return list(result.scalars().all())


async def count_tickets(
    session: AsyncSession, status: str | None = None, severity: str | None = None,
    scan_id: str | None = None, assignee: str | None = None,
) -> int:
    stmt = select(func.count(VulnTicket.id))
    if status:
        stmt = stmt.where(VulnTicket.status == status)
    if severity:
        stmt = stmt.where(VulnTicket.severity == severity)
    if scan_id:
        stmt = stmt.where(VulnTicket.scan_id == scan_id)
    if assignee:
        stmt = stmt.where(VulnTicket.assignee == assignee)
    result = await session.execute(stmt)
    return result.scalar_one()


async def create_ticket(session: AsyncSession, ticket: VulnTicket) -> VulnTicket:
    session.add(ticket)
    await session.commit()
    await session.refresh(ticket)
    return ticket


async def update_ticket(session: AsyncSession, ticket: VulnTicket) -> VulnTicket:
    await session.commit()
    await session.refresh(ticket)
    return ticket


async def delete_ticket(session: AsyncSession, ticket: VulnTicket) -> None:
    await session.delete(ticket)
    await session.commit()


async def search_tickets(
    session: AsyncSession, keyword: str, limit: int = 100,
) -> list[VulnTicket]:
    like = f"%{keyword}%"
    stmt = select(VulnTicket).where(
        or_(VulnTicket.title.like(like), VulnTicket.vuln_id.like(like))
    ).order_by(VulnTicket.created_at.desc()).limit(limit)
    result = await session.execute(stmt)
    return list(result.scalars().all())
