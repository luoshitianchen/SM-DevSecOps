"""漏洞工单管理路由。"""
from __future__ import annotations

from fastapi import APIRouter, Depends, Query, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_session
from app.schemas.vuln_ticket import TicketAssign, TicketCreate, TicketStatusUpdate
from app.services.vuln_ticket import TicketService

router = APIRouter(prefix="/api/vuln-tickets", tags=["vuln-tickets"])


@router.get("")
async def list_tickets(
    request: Request,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    status_filter: str | None = Query(default=None, alias="status"),
    severity: str | None = Query(default=None),
    scan_id: str | None = Query(default=None),
    assignee: str | None = Query(default=None),
    session: AsyncSession = Depends(get_session),
) -> dict:
    return await TicketService.list_tickets(session, limit=limit, offset=offset,
                                            status_filter=status_filter, severity=severity,
                                            scan_id=scan_id, assignee=assignee)


@router.get("/search")
async def search_tickets(
    request: Request,
    keyword: str = Query(default="", min_length=1),
    session: AsyncSession = Depends(get_session),
) -> dict:
    return await TicketService.search_tickets(session, keyword)


@router.post("", status_code=status.HTTP_201_CREATED)
async def create_ticket(
    payload: TicketCreate, request: Request,
    session: AsyncSession = Depends(get_session),
) -> dict:
    return await TicketService.create_ticket(session, payload, request)


@router.get("/{ticket_id}")
async def get_ticket(
    ticket_id: str, request: Request,
    session: AsyncSession = Depends(get_session),
) -> dict:
    return await TicketService.get_ticket(session, ticket_id)


@router.patch("/{ticket_id}/assign")
async def assign_ticket(
    ticket_id: str, payload: TicketAssign, request: Request,
    session: AsyncSession = Depends(get_session),
) -> dict:
    return await TicketService.assign_ticket(session, ticket_id, payload, request)


@router.patch("/{ticket_id}/status")
async def change_ticket_status(
    ticket_id: str, payload: TicketStatusUpdate, request: Request,
    session: AsyncSession = Depends(get_session),
) -> dict:
    return await TicketService.change_status(session, ticket_id, payload, request)


@router.delete("/{ticket_id}")
async def delete_ticket(
    ticket_id: str, request: Request,
    session: AsyncSession = Depends(get_session),
) -> dict:
    return await TicketService.delete_ticket(session, ticket_id, request)
