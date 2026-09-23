"""新增业务表：流水线、扫描结果与漏洞工单。

Revision ID: 0002_business_tables
Revises: 0001_initial
Create Date: 2026-09-23
"""
from __future__ import annotations
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa


# 本迁移的版本号，下游 0003 及以后迁移以此为 down_revision
revision: str = '0002_business_tables'
# 上一版本，承接 0001_initial
down_revision: Union[str, None] = '0001_initial'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ### Alembic 自动生成开始，按模型元数据建立业务表 ###
    # 流水线表：登记接入 DevSecOps 的 CI/CD 流水线
    op.create_table('pipelines',
    sa.Column('id', sa.String(length=64), nullable=False),
    sa.Column('pipeline_code', sa.String(length=128), nullable=False),
    sa.Column('name', sa.String(length=128), nullable=False),
    sa.Column('repo_url', sa.String(length=512), nullable=False),
    sa.Column('status', sa.String(length=16), nullable=False),
    sa.Column('triggers', sa.Text(), nullable=False),
    sa.Column('description', sa.String(length=512), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('(CURRENT_TIMESTAMP)'), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('(CURRENT_TIMESTAMP)'), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_pipelines_pipeline_code'), 'pipelines', ['pipeline_code'], unique=True)
    op.create_index(op.f('ix_pipelines_status'), 'pipelines', ['status'], unique=False)
    # 扫描结果表：记录每次安全扫描的结果与各级别漏洞数量
    op.create_table('scan_results',
    sa.Column('id', sa.String(length=64), nullable=False),
    sa.Column('scan_id', sa.String(length=128), nullable=False),
    sa.Column('pipeline_code', sa.String(length=128), nullable=False),
    sa.Column('scan_type', sa.String(length=32), nullable=False),
    sa.Column('status', sa.String(length=16), nullable=False),
    sa.Column('critical_count', sa.Integer(), nullable=False),
    sa.Column('high_count', sa.Integer(), nullable=False),
    sa.Column('medium_count', sa.Integer(), nullable=False),
    sa.Column('low_count', sa.Integer(), nullable=False),
    sa.Column('summary', sa.Text(), nullable=False),
    sa.Column('started_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('finished_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('(CURRENT_TIMESTAMP)'), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_scan_results_pipeline_code'), 'scan_results', ['pipeline_code'], unique=False)
    op.create_index(op.f('ix_scan_results_scan_id'), 'scan_results', ['scan_id'], unique=True)
    op.create_index(op.f('ix_scan_results_scan_type'), 'scan_results', ['scan_type'], unique=False)
    op.create_index(op.f('ix_scan_results_status'), 'scan_results', ['status'], unique=False)
    # 漏洞工单表：将扫描出的漏洞流转为跟踪工单
    op.create_table('vuln_tickets',
    sa.Column('id', sa.String(length=64), nullable=False),
    sa.Column('ticket_no', sa.String(length=128), nullable=False),
    sa.Column('scan_id', sa.String(length=128), nullable=False),
    sa.Column('vuln_id', sa.String(length=128), nullable=False),
    sa.Column('severity', sa.String(length=16), nullable=False),
    sa.Column('title', sa.String(length=256), nullable=False),
    sa.Column('status', sa.String(length=16), nullable=False),
    sa.Column('assignee', sa.String(length=128), nullable=False),
    sa.Column('description', sa.Text(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('(CURRENT_TIMESTAMP)'), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('(CURRENT_TIMESTAMP)'), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_vuln_tickets_scan_id'), 'vuln_tickets', ['scan_id'], unique=False)
    op.create_index(op.f('ix_vuln_tickets_severity'), 'vuln_tickets', ['severity'], unique=False)
    op.create_index(op.f('ix_vuln_tickets_status'), 'vuln_tickets', ['status'], unique=False)
    op.create_index(op.f('ix_vuln_tickets_ticket_no'), 'vuln_tickets', ['ticket_no'], unique=True)
    op.create_index(op.f('ix_vuln_tickets_vuln_id'), 'vuln_tickets', ['vuln_id'], unique=False)
    # ### Alembic 自动生成结束 ###


def downgrade() -> None:
    # ### Alembic 自动生成开始，按逆序删除业务表与索引 ###
    op.drop_index(op.f('ix_vuln_tickets_vuln_id'), table_name='vuln_tickets')
    op.drop_index(op.f('ix_vuln_tickets_ticket_no'), table_name='vuln_tickets')
    op.drop_index(op.f('ix_vuln_tickets_status'), table_name='vuln_tickets')
    op.drop_index(op.f('ix_vuln_tickets_severity'), table_name='vuln_tickets')
    op.drop_index(op.f('ix_vuln_tickets_scan_id'), table_name='vuln_tickets')
    op.drop_table('vuln_tickets')
    op.drop_index(op.f('ix_scan_results_status'), table_name='scan_results')
    op.drop_index(op.f('ix_scan_results_scan_type'), table_name='scan_results')
    op.drop_index(op.f('ix_scan_results_scan_id'), table_name='scan_results')
    op.drop_index(op.f('ix_scan_results_pipeline_code'), table_name='scan_results')
    op.drop_table('scan_results')
    op.drop_index(op.f('ix_pipelines_status'), table_name='pipelines')
    op.drop_index(op.f('ix_pipelines_pipeline_code'), table_name='pipelines')
    op.drop_table('pipelines')
    # ### Alembic 自动生成结束 ###
