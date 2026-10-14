"""Core operations shared by the API and the agents."""
import hashlib
import secrets
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .config import settings
from .identity import identifiers, keyed_hash, normalize_phone
from .models import (CheckLog, Dispute, Event, EventIdentity, EventStatus, EventType,
                     Identity, Merchant, utcnow)
from .scoring import score_events

VALID_TYPES = {t.value for t in EventType}


class ValidationError(ValueError):
    pass


def hash_api_key(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


def create_merchant(s: Session, name: str, country: str, agreement_signed: bool,
                    feed_config: dict | None = None) -> tuple[Merchant, str]:
    country = country.upper()
    if country not in ("PK", "AE"):
        raise ValidationError("country must be PK or AE")
    key = "cs_" + secrets.token_urlsafe(32)
    m = Merchant(name=name, country=country, api_key_hash=hash_api_key(key),
                 agreement_signed_at=utcnow() if agreement_signed else None,
                 feed_config=feed_config)
    s.add(m)
    s.commit()
    return m, key


def merchant_by_key(s: Session, key: str) -> Merchant | None:
    return s.scalar(select(Merchant).where(Merchant.api_key_hash == hash_api_key(key),
                                           Merchant.active.is_(True)))


def _get_or_create_identity(s: Session, kind: str, h: str, country: str) -> Identity:
    ident = s.scalar(select(Identity).where(Identity.hash == h))
    if ident is None:
        ident = Identity(kind=kind, hash=h, country=country)
        s.add(ident)
        s.flush()
    return ident


def prepare_event(merchant: Merchant, *, order_ref: str, type: str, occurred_at: datetime,
                  phone: str | None = None, email: str | None = None, address: str | None = None,
                  city: str | None = None, country: str | None = None, amount: float | None = None,
                  currency: str | None = None, evidence: str | None = None) -> dict:
    """Validate an outcome and hash its identifiers. The result holds no raw personal data."""
    if merchant.agreement_signed_at is None:
        raise ValidationError("merchant has no signed data-sharing agreement")
    if type not in VALID_TYPES:
        raise ValidationError(f"unknown event type '{type}'")
    if not order_ref:
        raise ValidationError("order_ref is required")
    country = (country or merchant.country).upper()
    if country not in ("PK", "AE"):
        raise ValidationError("country must be PK or AE")
    if occurred_at.tzinfo:
        occurred_at = occurred_at.astimezone(timezone.utc).replace(tzinfo=None)
    if occurred_at > utcnow() + timedelta(hours=1):
        raise ValidationError("occurred_at is in the future")
    if occurred_at < utcnow() - timedelta(days=settings.RETENTION_DAYS):
        raise ValidationError("event older than retention period")
    ids = identifiers(phone, email, address, city, country)
    if not any(k in ("phone", "email") for k, _ in ids):
        raise ValidationError("a valid phone or email is required (address alone is not enough)")
    return {"order_ref": str(order_ref)[:100], "type": type, "country": country, "amount": amount,
            "currency": currency, "occurred_at": occurred_at, "evidence": evidence,
            "identities": [list(x) for x in ids], "contact_hint": contact_hint(phone, email, country)}


def contact_hint(phone, email, country) -> str | None:
    """A masked contact for checkers to recognise an entry, e.g. +92•••••4567 or a•••@gmail.com."""
    p = normalize_phone(phone or "", country)
    if p:
        return p[:3] + "•" * max(len(p) - 7, 3) + p[-4:]
    if email and "@" in email:
        local, _, dom = email.strip().lower().partition("@")
        return (local[:1] or "") + "•••@" + dom
    return None


def commit_event(s: Session, merchant: Merchant, prepared: dict, source: str = "api") -> tuple[Event | None, str]:
    existing = s.scalar(select(Event).where(Event.merchant_id == merchant.id,
                                            Event.order_ref == prepared["order_ref"],
                                            Event.type == prepared["type"]))
    if existing:
        return existing, "duplicate"
    occurred = prepared["occurred_at"]
    if isinstance(occurred, str):
        occurred = datetime.fromisoformat(occurred)
    ev = Event(merchant_id=merchant.id, order_ref=prepared["order_ref"], type=prepared["type"],
               country=prepared["country"], amount=prepared.get("amount"), currency=prepared.get("currency"),
               occurred_at=occurred, evidence=prepared.get("evidence"), source=source)
    s.add(ev)
    try:
        s.flush()
        for kind, h in prepared["identities"]:
            ident = _get_or_create_identity(s, kind, h, prepared["country"])
            s.add(EventIdentity(event_id=ev.id, identity_id=ident.id))
        s.commit()
    except IntegrityError:
        s.rollback()
        return None, "duplicate"
    return ev, "created"


def report_event(s: Session, merchant: Merchant, *, source: str = "api", **fields) -> tuple[Event | None, str]:
    """Validate, hash and store in one step (API-key integrations and agents)."""
    return commit_event(s, merchant, prepare_event(merchant, **fields), source)


def check(s: Session, *, phone=None, email=None, address=None, city=None, country="PK",
          merchant: Merchant | None = None) -> dict:
    country = (country or "PK").upper()
    ids = identifiers(phone, email, address, city, country)
    if not ids:
        raise ValidationError("provide at least one valid phone, email or address")
    hashes = {h: k for k, h in ids}
    rows = s.execute(
        select(Event, Identity.hash, Merchant.trust_weight)
        .join(EventIdentity, EventIdentity.event_id == Event.id)
        .join(Identity, Identity.id == EventIdentity.identity_id)
        .join(Merchant, Merchant.id == Event.merchant_id)
        .where(Identity.hash.in_(hashes.keys()))
    ).all()
    result = score_events([(ev, hashes[h], tw) for ev, h, tw in rows])
    result["matched_on"] = sorted({hashes[h] for _, h, _ in rows})
    if merchant is not None:
        s.add(CheckLog(merchant_id=merchant.id, country=country,
                       score=result["score"], band=result["band"]))
        s.commit()
    return result


def open_dispute(s: Session, *, phone: str, country: str, reason: str, contact: str | None) -> Dispute:
    p = normalize_phone(phone, country)
    if not p:
        raise ValidationError("invalid phone number")
    ident = s.scalar(select(Identity).where(Identity.hash == keyed_hash("phone", p)))
    if ident is None:
        raise ValidationError("no records found for this number")
    d = Dispute(identity_id=ident.id, reason=reason[:2000], contact=contact)
    s.add(d)
    # freeze negative events tied to this identity while under review
    evs = s.scalars(select(Event).join(EventIdentity).where(
        EventIdentity.identity_id == ident.id, Event.status == EventStatus.ACTIVE.value,
        Event.type != EventType.DELIVERED_PAID.value)).all()
    for ev in evs:
        ev.status = EventStatus.DISPUTED.value
    s.commit()
    return d


def resolve_dispute(s: Session, dispute_id: int, upheld: bool, note: str | None) -> Dispute:
    d = s.get(Dispute, dispute_id)
    if d is None or d.status != "open":
        raise ValidationError("dispute not found or already resolved")
    new_status = EventStatus.REMOVED.value if upheld else EventStatus.ACTIVE.value
    evs = s.scalars(select(Event).join(EventIdentity).where(
        EventIdentity.identity_id == d.identity_id, Event.status == EventStatus.DISPUTED.value)).all()
    for ev in evs:
        ev.status = new_status
    d.status = "upheld" if upheld else "rejected"
    d.resolution_note = note
    d.resolved_at = utcnow()
    s.commit()
    return d
