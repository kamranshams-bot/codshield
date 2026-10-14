"""Database schema.

Privacy by design: no raw phone numbers, emails, names or addresses are stored.
Only keyed hashes (HMAC-SHA256) of normalized identifiers.
"""
from datetime import datetime, timezone
from enum import Enum

from sqlalchemy import (JSON, Boolean, DateTime, Float, ForeignKey, Integer,
                        String, Text, UniqueConstraint)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .db import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


class EventType(str, Enum):
    # negative signals
    REFUSED_AT_DOOR = "refused_at_door"          # customer refused COD parcel
    UNREACHABLE = "unreachable"                  # phone off / no answer on delivery
    FAKE_ADDRESS = "fake_address"                # address does not exist
    FAKE_ORDER = "fake_order"                    # customer denies placing order
    RETURN_ABUSE = "return_abuse"                # returned item used/swapped/damaged
    CHARGEBACK = "chargeback"                    # prepaid order charged back
    # positive signal (reduces score)
    DELIVERED_PAID = "delivered_paid"


class EventStatus(str, Enum):
    ACTIVE = "active"
    DISPUTED = "disputed"   # excluded from scoring while under review
    REMOVED = "removed"     # upheld dispute or merchant withdrawal


class Merchant(Base):
    __tablename__ = "merchants"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(200))
    country: Mapped[str] = mapped_column(String(2))           # PK / AE
    api_key_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    # contributors must sign a data-sharing agreement before reporting
    agreement_signed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    trust_weight: Mapped[float] = mapped_column(Float, default=1.0)  # lowered if abuse detected
    feed_config: Mapped[dict | None] = mapped_column(JSON, nullable=True)  # for ingestion agent
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class Identity(Base):
    __tablename__ = "identities"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    kind: Mapped[str] = mapped_column(String(10))            # phone / email / address
    hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    country: Mapped[str | None] = mapped_column(String(2), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class Event(Base):
    __tablename__ = "events"
    __table_args__ = (UniqueConstraint("merchant_id", "order_ref", "type", name="uq_event_dedupe"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    merchant_id: Mapped[int] = mapped_column(ForeignKey("merchants.id"), index=True)
    order_ref: Mapped[str] = mapped_column(String(100))      # merchant's own order id
    type: Mapped[str] = mapped_column(String(30))
    country: Mapped[str] = mapped_column(String(2))
    amount: Mapped[float | None] = mapped_column(Float, nullable=True)
    currency: Mapped[str | None] = mapped_column(String(3), nullable=True)
    occurred_at: Mapped[datetime] = mapped_column(DateTime, index=True)
    evidence: Mapped[str | None] = mapped_column(Text, nullable=True)  # e.g. courier ref; no PII
    status: Mapped[str] = mapped_column(String(10), default=EventStatus.ACTIVE.value, index=True)
    source: Mapped[str] = mapped_column(String(20), default="api")   # api / agent:<connector>
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

    identities: Mapped[list["Identity"]] = relationship(secondary="event_identities", lazy="selectin")


class EventIdentity(Base):
    __tablename__ = "event_identities"
    event_id: Mapped[int] = mapped_column(ForeignKey("events.id", ondelete="CASCADE"), primary_key=True)
    identity_id: Mapped[int] = mapped_column(ForeignKey("identities.id"), primary_key=True, index=True)


class Dispute(Base):
    __tablename__ = "disputes"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    identity_id: Mapped[int] = mapped_column(ForeignKey("identities.id"))
    reason: Mapped[str] = mapped_column(Text)
    contact: Mapped[str | None] = mapped_column(String(200), nullable=True)  # how to reply; consented
    status: Mapped[str] = mapped_column(String(10), default="open")  # open / upheld / rejected
    resolution_note: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class CheckLog(Base):
    """One row per risk check, for usage reports. Holds no customer identifiers."""
    __tablename__ = "check_logs"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    merchant_id: Mapped[int] = mapped_column(ForeignKey("merchants.id"), index=True)
    country: Mapped[str] = mapped_column(String(2))
    score: Mapped[int] = mapped_column(Integer)
    band: Mapped[str] = mapped_column(String(10))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)


class AgentRun(Base):
    __tablename__ = "agent_runs"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    agent: Mapped[str] = mapped_column(String(50))
    merchant_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    started_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    stats: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
