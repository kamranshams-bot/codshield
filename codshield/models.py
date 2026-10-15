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
    plan: Mapped[str] = mapped_column(String(20), default="free")
    require_approval: Mapped[bool] = mapped_column(Boolean, default=True)  # maker-checker for UI entries
    tier: Mapped[str] = mapped_column(String(20), default="contributor")   # contributor / score_only
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
    status: Mapped[str] = mapped_column(String(10), default="open")  # unverified / open / upheld / rejected
    verified: Mapped[bool] = mapped_column(Boolean, default=True)    # phone ownership proven by a code
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


# ---------------------------------------------------------------- SaaS: users & workflow
class Perm(str, Enum):
    CHECK = "check"          # check orders
    SUBMIT = "submit"        # maker: enter single outcomes
    UPLOAD = "upload"        # maker: bulk upload outcomes
    APPROVE = "approve"      # checker: approve / reject entries
    REPORTS = "reports"      # view reports
    DISPUTES = "disputes"    # respond to disputes about own records
    USERS = "users"          # tenant admin: manage users, API key, audit log


ALL_PERMS = [p.value for p in Perm]


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    merchant_id: Mapped[int | None] = mapped_column(ForeignKey("merchants.id"), nullable=True, index=True)
    email: Mapped[str] = mapped_column(String(200), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(120))
    password_hash: Mapped[str] = mapped_column(String(200))
    perms: Mapped[str] = mapped_column(String(200), default="check")       # comma list of Perm
    countries: Mapped[str] = mapped_column(String(20), default="PK,AE")     # comma list
    is_platform_admin: Mapped[bool] = mapped_column(Boolean, default=False)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    must_change_password: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class UserSession(Base):
    __tablename__ = "user_sessions"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class Submission(Base):
    """An outcome entered by a maker, waiting for a checker. Holds hashed identifiers only."""
    __tablename__ = "submissions"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    merchant_id: Mapped[int] = mapped_column(ForeignKey("merchants.id"), index=True)
    maker_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    batch_ref: Mapped[str | None] = mapped_column(String(40), nullable=True, index=True)
    status: Mapped[str] = mapped_column(String(10), default="pending", index=True)  # pending/approved/rejected
    country: Mapped[str] = mapped_column(String(2))
    payload: Mapped[dict] = mapped_column(JSON)          # order_ref, type, occurred_at, amount, ...
    identities: Mapped[list] = mapped_column(JSON)       # [[kind, hash], ...]
    contact_hint: Mapped[str | None] = mapped_column(String(40), nullable=True)  # masked, e.g. +92•••••4567
    checker_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    decided_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    reject_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    event_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)


class DisputeResponse(Base):
    __tablename__ = "dispute_responses"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    dispute_id: Mapped[int] = mapped_column(ForeignKey("disputes.id"), index=True)
    merchant_id: Mapped[int] = mapped_column(ForeignKey("merchants.id"))
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    action: Mapped[str] = mapped_column(String(10))      # withdraw / confirm
    note: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class AuditLog(Base):
    __tablename__ = "audit_log"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    merchant_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    user_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    actor: Mapped[str] = mapped_column(String(200))      # "user:email" / "api-key" / "admin-key"
    action: Mapped[str] = mapped_column(String(50), index=True)
    detail: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)


# ---------------------------------------------------------------- API platform
class ApiKey(Base):
    """A customer-managed API key. Only a hash is stored; the full key is shown once."""
    __tablename__ = "api_keys"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    merchant_id: Mapped[int] = mapped_column(ForeignKey("merchants.id"), index=True)
    name: Mapped[str] = mapped_column(String(80))
    key_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    prefix: Mapped[str] = mapped_column(String(20))            # e.g. cs_live_AbC1 (display only)
    mode: Mapped[str] = mapped_column(String(4), default="live")  # live / test
    scopes: Mapped[str] = mapped_column(String(40), default="check")  # comma list: check, report, read
    created_by: Mapped[int | None] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class ApiUsage(Base):
    """Daily call counters per key and endpoint, for usage reports and billing."""
    __tablename__ = "api_usage"
    __table_args__ = (UniqueConstraint("day", "key_id", "endpoint", name="uq_usage_day_key_ep"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    day: Mapped[str] = mapped_column(String(10), index=True)   # YYYY-MM-DD (UTC)
    merchant_id: Mapped[int] = mapped_column(Integer, index=True)
    key_id: Mapped[int] = mapped_column(Integer)                 # 0 = legacy store key
    endpoint: Mapped[str] = mapped_column(String(60))
    calls: Mapped[int] = mapped_column(Integer, default=0)
    errors: Mapped[int] = mapped_column(Integer, default=0)


class WebhookEndpoint(Base):
    __tablename__ = "webhook_endpoints"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    merchant_id: Mapped[int] = mapped_column(ForeignKey("merchants.id"), index=True)
    url: Mapped[str] = mapped_column(String(500))
    secret: Mapped[str] = mapped_column(String(80))              # signing secret (server-generated)
    events: Mapped[str] = mapped_column(String(300))             # comma list, or "*"
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class WebhookDelivery(Base):
    __tablename__ = "webhook_deliveries"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    endpoint_id: Mapped[int] = mapped_column(ForeignKey("webhook_endpoints.id", ondelete="CASCADE"), index=True)
    event_id: Mapped[str] = mapped_column(String(40), index=True)
    event: Mapped[str] = mapped_column(String(40))
    payload: Mapped[dict] = mapped_column(JSON)
    status: Mapped[str] = mapped_column(String(10), default="pending", index=True)  # pending/delivered/failed
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    response_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    last_attempt_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class PhoneVerification(Base):
    """A one-time code sent to a phone before a consumer dispute can freeze records."""
    __tablename__ = "phone_verifications"
    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    phone_hash: Mapped[str] = mapped_column(String(64), index=True)
    code_hash: Mapped[str] = mapped_column(String(64))
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime)
    verified_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    used_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class PasswordToken(Base):
    """Single-use link for password reset or a new user's invitation (only the hash is stored)."""
    __tablename__ = "password_tokens"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    purpose: Mapped[str] = mapped_column(String(10))            # reset / invite
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime)
    used_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class Integration(Base):
    """A store's connected shop (Shopify). Secrets are encrypted at rest."""
    __tablename__ = "integrations"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    merchant_id: Mapped[int] = mapped_column(ForeignKey("merchants.id"), index=True)
    kind: Mapped[str] = mapped_column(String(20))                # shopify
    shop: Mapped[str] = mapped_column(String(200))               # mystore.myshopify.com
    client_id: Mapped[str | None] = mapped_column(String(200), nullable=True)
    secret_enc: Mapped[str] = mapped_column(Text)                # client secret (or admin token), encrypted
    token_enc: Mapped[str | None] = mapped_column(Text, nullable=True)
    token_expires_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    settings: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_event_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    stats: Mapped[dict | None] = mapped_column(JSON, nullable=True)
