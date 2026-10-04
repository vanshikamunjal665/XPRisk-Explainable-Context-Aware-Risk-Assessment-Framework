"""SQLAlchemy ORM models for XPRisk persistence (Phase 7).

Storage only: no risk computation, no context analysis, no decisions.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy import JSON, Boolean, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.app.database.database import Base

# JSON on SQLite, JSONB on PostgreSQL.
JsonType = JSON().with_variant(JSONB(), "postgresql")


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Deployment(Base):
    __tablename__ = "deployments"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    commit_id: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    branch: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    environment: Mapped[str] = mapped_column(String(64), nullable=False, default="development")
    internet_exposed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow)
    risk_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    decision: Mapped[str | None] = mapped_column(String(32), nullable=True)

    findings: Mapped[list["Finding"]] = relationship(
        back_populates="deployment", cascade="all, delete-orphan", lazy="selectin"
    )
    risk_factors: Mapped[list["RiskFactor"]] = relationship(
        back_populates="deployment", cascade="all, delete-orphan", lazy="selectin"
    )


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    deployment_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("deployments.id", ondelete="CASCADE"), nullable=False, index=True
    )
    tool: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    category: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    severity: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    finding_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    resource: Mapped[str | None] = mapped_column(Text, nullable=True)
    file: Mapped[str | None] = mapped_column(Text, nullable=True)
    line: Mapped[int | None] = mapped_column(Integer, nullable=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    metadata_: Mapped[dict[str, Any]] = mapped_column("metadata", JsonType, nullable=False, default=dict)

    deployment: Mapped["Deployment"] = relationship(back_populates="findings")


class RiskFactor(Base):
    __tablename__ = "risk_factors"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    deployment_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("deployments.id", ondelete="CASCADE"), nullable=False, index=True
    )
    factor_name: Mapped[str] = mapped_column(String(128), nullable=False)
    factor_value: Mapped[Any] = mapped_column(JsonType, nullable=True)
    contribution: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)

    deployment: Mapped["Deployment"] = relationship(back_populates="risk_factors")
