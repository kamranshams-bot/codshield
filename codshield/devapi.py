"""Developer API platform: customer API keys, sandbox (test mode), usage metering, webhooks."""
import hashlib
import hmac
import ipaddress
import json
import logging
import os
import secrets
import socket
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from urllib.parse import urlparse

import httpx
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .db import SessionLocal
from .identity import normalize_email, normalize_phone
from .models import (ApiKey, ApiUsage, Merchant, WebhookDelivery,
                     WebhookEndpoint, utcnow)

log = logging.getLogger("codshield.platform")

SCOPES = {
    "check": "Check orders (single and batch)",
    "report": "Report outcomes (single and batch)",
    "read": "Read reports, entries and usage",
}
TIERS = {"contributor": "Contributor", "score_only": "Score-only"}

# Requests per minute per API key, by plan.
PLAN_RATE = {"free": 60, "growth": 600, "enterprise": 3000}

WEBHOOK_EVENTS = {
    "entry.approved": "Entries you submitted were approved and now count in the network",
    "entry.rejected": "Entries were rejected by a checker (with the reason)",
    "dispute.opened": "A customer contested records your store reported",
    "dispute.resolved": "CODShield decided a dispute involving your records",
    "quota.warning": "Your store has used 80% of this month's order checks",
}
MAX_ATTEMPTS = 6


class PlatformError(Exception):
    def __init__(self, status: int, msg: str):
        super().__init__(msg)
        self.status = status


# ------------------------------------------------------------------ API keys
def _hash(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


def create_api_key(s: Session, m: Merchant, *, name: str, mode: str, scopes: list[str],
                   created_by: int | None) -> tuple[ApiKey, str]:
    if mode not in ("live", "test"):
        raise PlatformError(422, "Mode must be live or test.")
    scopes = [x for x in SCOPES if x in set(scopes)]
    if not scopes:
        raise PlatformError(422, "Choose at least one scope.")
    if "report" in scopes and m.tier == "score_only":
        raise PlatformError(403, "Score-only stores can't report outcomes. Ask CODShield to switch to the contributor tier.")
    active = s.scalar(select(func.count(ApiKey.id)).where(ApiKey.merchant_id == m.id, ApiKey.revoked_at.is_(None))) or 0
    if active >= 20:
        raise PlatformError(422, "A store can have up to 20 active keys. Revoke one first.")
    key = f"cs_{mode}_" + secrets.token_urlsafe(30)
    k = ApiKey(merchant_id=m.id, name=(name or "API key").strip()[:80], key_hash=_hash(key),
               prefix=key[:12], mode=mode, scopes=",".join(scopes), created_by=created_by)
    s.add(k)
    s.commit()
    return k, key


def find_api_key(s: Session, key: str) -> ApiKey | None:
    k = s.scalar(select(ApiKey).where(ApiKey.key_hash == _hash(key)))
    if not k or k.revoked_at is not None:
        return None
    return k


def key_view(k: ApiKey) -> dict:
    return {"id": k.id, "name": k.name, "prefix": k.prefix + "…", "mode": k.mode,
            "scopes": [x for x in k.scopes.split(",") if x],
            "created_at": k.created_at.isoformat(), "last_used_at": k.last_used_at.isoformat() if k.last_used_at else None,
            "revoked": k.revoked_at is not None}


# ------------------------------------------------------------------ usage metering
def endpoint_label(method: str, path: str) -> str:
    parts = [p if not p.isdigit() else "{id}" for p in path.strip("/").split("/")]
    return f"{method} /" + "/".join(parts)


def record_usage(s: Session, merchant_id: int, key_id: int, endpoint: str, error: bool = False) -> None:
    day = utcnow().date().isoformat()
    for _ in range(2):
        row = s.scalar(select(ApiUsage).where(ApiUsage.day == day, ApiUsage.key_id == key_id,
                                              ApiUsage.endpoint == endpoint, ApiUsage.merchant_id == merchant_id))
        if row:
            row.calls += 1
            row.errors += 1 if error else 0
            s.commit()
            return
        try:
            s.add(ApiUsage(day=day, merchant_id=merchant_id, key_id=key_id, endpoint=endpoint, calls=1, errors=int(error)))
            s.commit()
            return
        except IntegrityError:
            s.rollback()


def usage_report(s: Session, merchant_id: int, days: int = 30) -> dict:
    days = max(1, min(int(days), 90))
    start = (utcnow() - timedelta(days=days)).date().isoformat()
    rows = s.execute(select(ApiUsage.day, ApiUsage.key_id, ApiUsage.endpoint, ApiUsage.calls, ApiUsage.errors)
                     .where(ApiUsage.merchant_id == merchant_id, ApiUsage.day >= start)).all()
    names = {k.id: f"{k.name} ({k.prefix}…)" for k in s.scalars(select(ApiKey).where(ApiKey.merchant_id == merchant_id))}
    names[0] = "Original store key"
    by_day, by_key, by_ep = {}, {}, {}
    total = errs = 0
    for d, kid, ep, c, e in rows:
        by_day[d] = by_day.get(d, 0) + c
        kn = names.get(kid, f"key #{kid}")
        by_key[kn] = by_key.get(kn, 0) + c
        by_ep[ep] = by_ep.get(ep, 0) + c
        total += c
        errs += e
    dates = [(utcnow() - timedelta(days=days - i)).date().isoformat() for i in range(days + 1)]
    return {"days": days, "total_calls": total, "error_calls": errs,
            "daily": {"dates": dates, "calls": [by_day.get(d, 0) for d in dates]},
            "by_key": sorted(by_key.items(), key=lambda x: -x[1]),
            "by_endpoint": sorted(by_ep.items(), key=lambda x: -x[1])}


# ------------------------------------------------------------------ sandbox (test mode)
# Magic numbers: last digit picks the outcome, so integrators can test every branch.
SANDBOX_NUMBERS = {
    "+923000000001": ("high", 86, ["2 x refused_at_door", "1 x fake_order", "reported by 3 merchant(s)"]),
    "+923000000002": ("medium", 44, ["1 x refused_at_door", "1 x unreachable", "reported by 2 merchant(s)"]),
    "+923000000003": ("low", 0, ["no history in network"]),
    "+971500000001": ("high", 79, ["1 x return_abuse", "1 x chargeback", "reported by 2 merchant(s)"]),
    "+971500000002": ("medium", 38, ["1 x fake_address", "reported by 2 merchant(s)", "1 successful paid deliveries"]),
    "+971500000003": ("low", 0, ["no history in network"]),
}
_ACTIONS = {"low": "ship_normally", "medium": "confirm_by_call_or_otp", "high": "require_prepayment_or_partial_advance"}


def sandbox_check(phone: str | None, email: str | None, country: str) -> dict:
    p = normalize_phone(phone or "", country)
    if not p and not normalize_email(email or ""):
        raise PlatformError(422, "provide at least one valid phone, email or address")
    band, score, reasons = SANDBOX_NUMBERS.get(p or "", ("low", 0, ["no history in network"]))
    neg = 0 if band == "low" else 2
    return {"score": score, "band": band, "recommended_action": _ACTIONS[band], "reasons": reasons,
            "negative_events": neg, "paid_deliveries": 0, "reporting_merchants": 0 if band == "low" else 2,
            "last_negative_at": None, "matched_on": ["phone"] if neg else [], "test_mode": True}


def score_only_view(result: dict) -> dict:
    """Score-only stores see the decision, not the network's detailed history."""
    return {"score": result["score"], "band": result["band"], "recommended_action": result["recommended_action"],
            "matched_on": result.get("matched_on", []), "detail": "score_only_tier"}


# ------------------------------------------------------------------ webhooks
SYNC = False                       # tests deliver inline
_client_factory = lambda: httpx.Client(timeout=5)   # noqa: E731  (tests swap this)
_pool = ThreadPoolExecutor(max_workers=4)


def _allow_private() -> bool:
    return os.getenv("CODSHIELD_WEBHOOKS_ALLOW_PRIVATE") == "1"


def validate_url(url: str) -> None:
    u = urlparse(url.strip())
    if u.scheme != "https" and not (_allow_private() and u.scheme == "http"):
        raise PlatformError(422, "Webhook URLs must start with https://")
    if not u.hostname:
        raise PlatformError(422, "That isn't a valid URL.")
    if _allow_private():
        return
    try:
        infos = socket.getaddrinfo(u.hostname, u.port or 443, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        raise PlatformError(422, "That web address doesn't resolve. Check the domain name.")
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast or ip.is_unspecified:
            raise PlatformError(422, "Webhook URLs must point to a public internet address.")


def create_endpoint(s: Session, m: Merchant, url: str, events: list[str]) -> tuple[WebhookEndpoint, str]:
    validate_url(url)
    ev = [e for e in events if e in WEBHOOK_EVENTS]
    if not ev:
        raise PlatformError(422, "Choose at least one event.")
    if (s.scalar(select(func.count(WebhookEndpoint.id)).where(WebhookEndpoint.merchant_id == m.id,
                                                              WebhookEndpoint.active.is_(True))) or 0) >= 5:
        raise PlatformError(422, "A store can have up to 5 active webhook endpoints.")
    secret = "whsec_" + secrets.token_urlsafe(24)
    ep = WebhookEndpoint(merchant_id=m.id, url=url.strip(), secret=secret, events=",".join(ev))
    s.add(ep)
    s.commit()
    return ep, secret


def endpoint_view(ep: WebhookEndpoint, s: Session) -> dict:
    recent = s.scalars(select(WebhookDelivery).where(WebhookDelivery.endpoint_id == ep.id)
                       .order_by(WebhookDelivery.created_at.desc()).limit(10)).all()
    return {"id": ep.id, "url": ep.url, "events": ep.events.split(","), "active": ep.active,
            "secret_hint": ep.secret[:10] + "…", "created_at": ep.created_at.isoformat(),
            "recent": [{"id": d.id, "event": d.event, "status": d.status, "attempts": d.attempts,
                        "response_code": d.response_code, "error": d.last_error,
                        "at": (d.last_attempt_at or d.created_at).isoformat()} for d in recent]}


def sign(secret: str, body: bytes, ts: int) -> str:
    mac = hmac.new(secret.encode(), f"{ts}.".encode() + body, hashlib.sha256).hexdigest()
    return f"t={ts},v1={mac}"


def emit(s: Session, merchant_id: int, event: str, data: dict) -> int:
    """Queue an event for every subscribed endpoint of a store; returns deliveries queued."""
    eps = s.scalars(select(WebhookEndpoint).where(WebhookEndpoint.merchant_id == merchant_id,
                                                  WebhookEndpoint.active.is_(True))).all()
    eps = [e for e in eps if event in e.events.split(",") or e.events == "*" or event == "ping"]
    if not eps:
        return 0
    event_id = "evt_" + secrets.token_hex(10)
    payload = {"id": event_id, "type": event, "created_at": utcnow().isoformat() + "Z", "data": data}
    ids = []
    for ep in eps:
        d = WebhookDelivery(endpoint_id=ep.id, event_id=event_id, event=event, payload=payload)
        s.add(d)
        s.flush()
        ids.append(d.id)
    s.commit()
    for i in ids:
        if SYNC:
            deliver(i)
        else:
            _pool.submit(deliver, i)
    return len(ids)


def deliver(delivery_id: int) -> str:
    with SessionLocal() as s:
        d = s.get(WebhookDelivery, delivery_id)
        if not d or d.status == "delivered":
            return d.status if d else "missing"
        ep = s.get(WebhookEndpoint, d.endpoint_id)
        d.attempts += 1
        d.last_attempt_at = utcnow()
        try:
            if not ep or not ep.active:
                raise RuntimeError("endpoint disabled")
            validate_url(ep.url)                      # re-check at send time (DNS can change)
            body = json.dumps(d.payload, separators=(",", ":")).encode()
            ts = int(time.time())
            with _client_factory() as c:
                r = c.post(ep.url, content=body, headers={
                    "Content-Type": "application/json", "User-Agent": "CODShield-Webhooks/1",
                    "X-CODShield-Event": d.event, "X-CODShield-Delivery": str(d.id),
                    "X-CODShield-Signature": sign(ep.secret, body, ts)}, follow_redirects=False)
            d.response_code = r.status_code
            if 200 <= r.status_code < 300:
                d.status, d.last_error = "delivered", None
            else:
                raise RuntimeError(f"HTTP {r.status_code}")
        except Exception as e:
            d.last_error = str(e)[:300]
            d.status = "failed" if d.attempts >= MAX_ATTEMPTS else "pending"
        s.commit()
        return d.status


def retry_due(s: Session) -> int:
    """Called by the maintenance agent: retry pending deliveries with exponential backoff."""
    now = utcnow()
    n = 0
    for d in s.scalars(select(WebhookDelivery).where(WebhookDelivery.status == "pending",
                                                     WebhookDelivery.attempts > 0)).all():
        wait = timedelta(minutes=2 ** d.attempts)        # 2, 4, 8, 16, 32 minutes
        if d.last_attempt_at and now - d.last_attempt_at >= wait:
            deliver(d.id)
            n += 1
    return n
