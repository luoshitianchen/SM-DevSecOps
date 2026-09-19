"""漏洞工单服务层：闭环状态机管理。"""
from __future__ import annotations

import uuid

from fastapi import HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import internal_write_allowed
from app.models.vuln_ticket import VulnTicket
from app.repositories import scan_result as scan_repo
from app.repositories import vuln_ticket as repo
from app.schemas.vuln_ticket import TicketAssign, TicketCreate, TicketStatusUpdate
from app.services.audit import record_audit

# 工单合法闭环迁移表
_TRANSITIONS: dict[str, set[str]] = {
    "open": {"in_progress"},
    "in_progress": {"fixed"},
    "fixed": {"closed"},
    "closed": set(),
}


def _ticket_to_dict(t: VulnTicket) -> dict:
    return {
        "id": t.id, "ticket_no": t.ticket_no, "scan_id": t.scan_id, "vuln_id": t.vuln_id,
        "severity": t.severity, "title": t.title, "status": t.status,
        "assignee": t.assignee or "", "description": t.description or "",
        "created_at": t.created_at.isoformat() if t.created_at else "",
        "updated_at": t.updated_at.isoformat() if t.updated_at else "",
    }


class TicketService:
    @staticmethod
    async def list_tickets(session, limit, offset, status_filter, severity, scan_id, assignee) -> dict:
        items = await repo.list_tickets(session, limit=limit, offset=offset, status=status_filter,
                                        severity=severity, scan_id=scan_id, assignee=assignee)
        total = await repo.count_tickets(session, status=status_filter, severity=severity,
                                         scan_id=scan_id, assignee=assignee)
        return {"total": total, "items": [_ticket_to_dict(t) for t in items]}

    @staticmethod
    async def get_ticket(session: AsyncSession, ticket_id: str) -> dict:
        item = await repo.get_ticket(session, ticket_id)
        if not item:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "工单不存在")
        return _ticket_to_dict(item)

    @staticmethod
    async def search_tickets(session: AsyncSession, keyword: str) -> dict:
        items = await repo.search_tickets(session, keyword)
        return {"total": len(items), "items": [_ticket_to_dict(t) for t in items]}

    @staticmethod
    async def create_ticket(session: AsyncSession, payload: TicketCreate, request: Request) -> dict:
        if not internal_write_allowed(request):
            raise HTTPException(status.HTTP_403_FORBIDDEN, "内部写入令牌无效")
        # 工单必须来自一次已完成的扫描
        scan = await scan_repo.get_scan_by_scan_id(session, payload.scan_id)
        if not scan:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "来源扫描不存在")
        if await repo.get_ticket_by_no(session, payload.ticket_no):
            raise HTTPException(status.HTTP_409_CONFLICT, "工单编号已存在")
        item = VulnTicket(
            id=str(uuid.uuid4()), ticket_no=payload.ticket_no, scan_id=payload.scan_id,
            vuln_id=payload.vuln_id, severity=payload.severity, title=payload.title,
            assignee=payload.assignee, description=payload.description, status="open",
        )
        item = await repo.create_ticket(session, item)
        await record_audit(session, "ticket.created", "internal",
                           f"ticket_no={payload.ticket_no} vuln={payload.vuln_id}", request)
        return _ticket_to_dict(item)

    @staticmethod
    async def assign_ticket(session: AsyncSession, ticket_id: str, payload: TicketAssign,
                            request: Request) -> dict:
        if not internal_write_allowed(request):
            raise HTTPException(status.HTTP_403_FORBIDDEN, "内部写入令牌无效")
        item = await repo.get_ticket(session, ticket_id)
        if not item:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "工单不存在")
        item.assignee = payload.assignee
        item = await repo.update_ticket(session, item)
        await record_audit(session, "ticket.assigned", "internal",
                           f"ticket_no={item.ticket_no} assignee={payload.assignee}", request)
        return _ticket_to_dict(item)

    @staticmethod
    async def change_status(session: AsyncSession, ticket_id: str, payload: TicketStatusUpdate,
                            request: Request) -> dict:
        if not internal_write_allowed(request):
            raise HTTPException(status.HTTP_403_FORBIDDEN, "内部写入令牌无效")
        item = await repo.get_ticket(session, ticket_id)
        if not item:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "工单不存在")
        new_status = payload.status
        if new_status == item.status:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "目标状态与当前状态一致")
        if new_status not in _TRANSITIONS.get(item.status, set()):
            raise HTTPException(status.HTTP_409_CONFLICT,
                                f"非法状态迁移: {item.status} -> {new_status}")
        item.status = new_status
        item = await repo.update_ticket(session, item)
        await record_audit(session, "ticket.status_changed", "internal",
                           f"ticket_no={item.ticket_no} status={new_status}", request)
        return _ticket_to_dict(item)

    @staticmethod
    async def delete_ticket(session: AsyncSession, ticket_id: str, request: Request) -> dict:
        if not internal_write_allowed(request):
            raise HTTPException(status.HTTP_403_FORBIDDEN, "内部写入令牌无效")
        item = await repo.get_ticket(session, ticket_id)
        if not item:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "工单不存在")
        no = item.ticket_no
        await repo.delete_ticket(session, item)
        await record_audit(session, "ticket.deleted", "internal", f"ticket_no={no}", request)
        return {"deleted": True, "id": ticket_id}
