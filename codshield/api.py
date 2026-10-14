"""CODShield HTTP API (multi-tenant SaaS).

Run:  uvicorn codshield.api:app --reload
Docs: http://localhost:8000/docs
"""
import os
import secrets
import time
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path
from typing import Literal

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from . import auth, reports, service, workflow
from .auth import Actor, AuthError, PLANS, audit
from .config import settings
from .db import get_session, init_db
from .models import (ALL_PERMS, AuditLog, Dispute, Event, Identity, Merchant,
                     Submission, User, utcnow)

STATIC = Path(__file__).parent / "static"


@asynccontextmanager
async def lifespan(_app):
    init_db()
    yield


app = FastAPI(lifespan=lifespan, title="CODShield", version="0.3.0",
              description="Shared COD / return-abuse risk network for Pakistan and UAE merchants. "
                          "Stores hashed identifiers only. Multi-tenant with role-based access.")


@app.exception_handler(AuthError)
async def _auth_error(_req, exc: AuthError):
    return JSONResponse(status_code=exc.status, content={"detail": str(exc)})


def _setup_problems() -> list[str]:
    """On a hosted deployment, refuse to handle data until real secrets are set."""
    if not (os.getenv("RENDER") or os.getenv("CODSHIELD_PRODUCTION")):
        return []
    missing = []
    if settings.DATABASE_URL.startswith("sqlite"):
        missing.append("DATABASE_URL")
    if settings.HASH_SECRET == "dev-only-change-me" or len(settings.HASH_SECRET) < 32:
        missing.append("CODSHIELD_HASH_SECRET")
    if settings.ADMIN_KEY == "dev-admin-key" or len(settings.ADMIN_KEY) < 16:
        missing.append("CODSHIELD_ADMIN_KEY")
    return missing


@app.middleware("http")
async def require_configuration(request, call_next):
    if request.url.path.startswith("/v1/"):
        missing = _setup_problems()
        if missing:
            return JSONResponse(status_code=503, content={
                "detail": "This CODShield server isn't set up yet: missing " + ", ".join(missing) + "."})
    return await call_next(request)


# ---------- rate limit ----------
_hits: dict[str, deque] = defaultdict(deque)


def _rate_limit(key: str, per_min: int | None = None):
    now = time.time()
    q = _hits[key]
    while q and now - q[0] > 60:
        q.popleft()
    if len(q) >= (per_min or settings.RATE_LIMIT_PER_MIN):
        raise HTTPException(429, "Too many requests. Wait a minute and try again.")
    q.append(now)


# ---------- who is calling ----------
def get_actor(authorization: str | None = Header(None), x_api_key: str | None = Header(None),
              x_admin_key: str | None = Header(None), s: Session = Depends(get_session)) -> Actor:
    if authorization and authorization.lower().startswith("bearer "):
        u = auth.user_for_token(s, authorization[7:].strip())
        if not u:
            raise HTTPException(401, "Your session has ended. Sign in again.")
        a = auth.actor_for_user(s, u)
        _rate_limit(f"u{u.id}")
        return a
    if x_api_key:
        m = service.merchant_by_key(s, x_api_key)
        if m is None:
            raise HTTPException(401, "invalid API key")
        _rate_limit(f"m{m.id}")
        return auth.actor_for_api_key(m)
    if x_admin_key:
        if x_admin_key != settings.ADMIN_KEY:
            raise HTTPException(401, "invalid admin key")
        return auth.actor_for_admin_key()
    raise HTTPException(401, "Sign in, or send an API key.")


def platform(actor: Actor = Depends(get_actor)) -> Actor:
    actor.require_platform()
    return actor


def _bad(e: Exception):
    raise HTTPException(422, str(e))


# ---------- schemas ----------
Country = Literal["PK", "AE"]
PlanName = Literal["free", "growth", "enterprise"]


class CheckIn(BaseModel):
    phone: str | None = None
    email: str | None = None
    address: str | None = None
    city: str | None = None
    country: Country = "PK"


class EventIn(BaseModel):
    order_ref: str = Field(..., max_length=100)
    type: str = Field(..., examples=["refused_at_door"])
    occurred_at: datetime
    phone: str | None = None
    email: str | None = None
    address: str | None = None
    city: str | None = None
    country: Country | None = None
    amount: float | None = None
    currency: str | None = Field(None, max_length=3)
    evidence: str | None = Field(None, max_length=500,
                                 description="courier tracking id or note; do not include personal data")


class DisputeIn(BaseModel):
    phone: str
    country: Country
    reason: str = Field(..., min_length=10, max_length=2000)
    contact: str | None = Field(None, max_length=200)


class MerchantIn(BaseModel):
    name: str
    country: Country
    agreement_signed: bool = False
    feed_config: dict | None = None
    plan: PlanName = "free"
    require_approval: bool = True
    admin_email: str | None = None
    admin_name: str | None = None


class MerchantPatch(BaseModel):
    plan: PlanName | None = None
    require_approval: bool | None = None
    agreement_signed: bool | None = None
    active: bool | None = None


class ResolveIn(BaseModel):
    upheld: bool
    note: str | None = None


class LoginIn(BaseModel):
    email: str
    password: str


class SetupIn(BaseModel):
    email: str
    name: str
    password: str


class PasswordIn(BaseModel):
    current_password: str
    new_password: str


class UserIn(BaseModel):
    email: str
    name: str = ""
    perms: list[str] = ["check"]
    countries: list[Country] = ["PK", "AE"]
    merchant_id: int | None = None          # platform admins only
    is_platform_admin: bool = False         # platform admins only


class UserPatch(BaseModel):
    name: str | None = None
    perms: list[str] | None = None
    countries: list[Country] | None = None
    active: bool | None = None
    reset_password: bool = False


class DecideIn(BaseModel):
    ids: list[int]
    reason: str | None = None


class RespondIn(BaseModel):
    action: Literal["withdraw", "confirm"]
    note: str | None = Field(None, max_length=2000)


class TenantPatch(BaseModel):
    require_approval: bool | None = None


# ================================================================ public
@app.get("/", include_in_schema=False)
def home():
    return FileResponse(STATIC / "index.html")


@app.get("/health")
def health():
    return {"ok": True}


@app.get("/v1/meta", tags=["public"])
def meta(s: Session = Depends(get_session)):
    """What the sign-in screen needs to know."""
    has_admin = s.scalar(select(func.count(User.id)).where(User.is_platform_admin.is_(True))) > 0
    return {"setup_required": not has_admin, "permissions": ALL_PERMS, "plans": PLANS}


@app.post("/v1/disputes", tags=["public"], summary="A consumer contests records linked to their phone number")
def create_dispute(body: DisputeIn, s: Session = Depends(get_session)):
    _rate_limit("disputes")
    try:
        d = service.open_dispute(s, phone=body.phone, country=body.country, reason=body.reason, contact=body.contact)
    except service.ValidationError as e:
        _bad(e)
    audit(s, None, "dispute.opened", f"dispute #{d.id}", merchant_id=None)
    return {"dispute_id": d.id, "status": d.status, "message": "Records are excluded from scoring while we review."}


# ================================================================ sign in
@app.post("/v1/auth/setup", tags=["auth"], summary="Create the first platform administrator (needs the admin key)")
def setup(body: SetupIn, x_admin_key: str = Header(...), s: Session = Depends(get_session)):
    if x_admin_key != settings.ADMIN_KEY:
        raise HTTPException(401, "That admin key isn't correct.")
    if s.scalar(select(func.count(User.id)).where(User.is_platform_admin.is_(True))):
        raise HTTPException(409, "A platform administrator already exists. Sign in instead.")
    u, _ = auth.create_user(s, merchant=None, email=body.email, name=body.name, perms=ALL_PERMS,
                            countries=["PK", "AE"], is_platform_admin=True, password=body.password)
    u.must_change_password = False
    s.commit()
    audit(s, auth.actor_for_user(s, u), "platform.setup", f"first platform admin {u.email}")
    return {"token": auth.create_session(s, u)}


@app.post("/v1/auth/login", tags=["auth"])
def login(body: LoginIn, request: Request, s: Session = Depends(get_session)):
    ip = request.client.host if request.client else "?"
    _rate_limit(f"login:{ip}", 60)
    _rate_limit(f"login:{body.email.lower()}", 8)
    u = s.scalar(select(User).where(func.lower(User.email) == body.email.strip().lower()))
    if not u or not auth.verify_password(body.password, u.password_hash):
        raise HTTPException(401, "That email and password don't match.")
    if not u.active:
        raise HTTPException(403, "This account is switched off. Ask your administrator.")
    if u.merchant_id:
        m = s.get(Merchant, u.merchant_id)
        if not m or not m.active:
            raise HTTPException(403, "Your store's account is suspended. Contact CODShield.")
    token = auth.create_session(s, u)
    audit(s, auth.actor_for_user(s, u), "auth.login", "", merchant_id=u.merchant_id)
    return {"token": token}


@app.post("/v1/auth/logout", tags=["auth"])
def logout(authorization: str | None = Header(None), s: Session = Depends(get_session)):
    if authorization and authorization.lower().startswith("bearer "):
        auth.end_session(s, authorization[7:].strip())
    return {"ok": True}


@app.get("/v1/me", tags=["auth"])
def me(actor: Actor = Depends(get_actor), s: Session = Depends(get_session)):
    out = {"kind": actor.kind, "is_platform": actor.is_platform, "perms": sorted(actor.perms),
           "countries": sorted(actor.countries),
           "user": auth.public_user(actor.user) if actor.user else None, "tenant": None}
    if actor.merchant:
        m = actor.merchant
        plan = PLANS.get(m.plan or "free", PLANS["free"])
        out["tenant"] = {"id": m.id, "name": m.name, "country": m.country, "plan": m.plan or "free",
                         "plan_label": plan["label"], "require_approval": m.require_approval,
                         "seats_used": auth.seats_used(s, m.id), "seats_limit": plan["seats"],
                         "checks_this_month": auth.checks_this_month(s, m.id), "checks_limit": plan["checks"],
                         "agreement_signed": m.agreement_signed_at is not None}
        if "approve" in actor.perms:
            out["pending_approvals"] = s.scalar(select(func.count(Submission.id)).where(
                Submission.merchant_id == m.id, Submission.status == "pending",
                Submission.country.in_(actor.countries))) or 0
    return out


@app.post("/v1/auth/password", tags=["auth"])
def change_password(body: PasswordIn, actor: Actor = Depends(get_actor), s: Session = Depends(get_session)):
    if not actor.user:
        raise HTTPException(400, "Only signed-in users have passwords.")
    if not auth.verify_password(body.current_password, actor.user.password_hash):
        raise HTTPException(401, "Your current password isn't correct.")
    auth.check_password_strength(body.new_password)
    u = s.get(User, actor.user.id)
    u.password_hash, u.must_change_password = auth.hash_password(body.new_password), False
    s.commit()
    audit(s, actor, "auth.password_changed")
    return {"ok": True}


# ================================================================ store work
@app.post("/v1/check", tags=["store"])
def check(body: CheckIn, actor: Actor = Depends(get_actor), s: Session = Depends(get_session)):
    actor.require("check")
    actor.require_country(body.country)
    if actor.merchant:
        auth.check_quota(s, actor.merchant)
    try:
        return service.check(s, merchant=actor.merchant, **body.model_dump())
    except service.ValidationError as e:
        _bad(e)


@app.post("/v1/check/batch", tags=["store"], summary="Check up to 500 orders in one call")
def check_batch(body: list[CheckIn], actor: Actor = Depends(get_actor), s: Session = Depends(get_session)):
    actor.require("check")
    if len(body) > 500:
        raise HTTPException(413, "max 500 orders per batch")
    if actor.merchant:
        auth.check_quota(s, actor.merchant, len(body))
    results = []
    for i, item in enumerate(body):
        try:
            actor.require_country(item.country)
            results.append({"index": i, "ok": True, **service.check(s, merchant=actor.merchant, **item.model_dump())})
        except (service.ValidationError, AuthError) as e:
            results.append({"index": i, "ok": False, "error": str(e)})
    return {"results": results}


@app.post("/v1/events", tags=["store"], status_code=201,
          summary="Report one outcome (API keys record directly; users go through approval if required)")
def report(body: EventIn, actor: Actor = Depends(get_actor), s: Session = Depends(get_session)):
    r = workflow.submit(s, actor, [body.model_dump()], bulk=False)
    first = r["results"][0]
    if first["outcome"] == "rejected":
        raise AuthError(403, first["error"]) if "isn't set up for" in first["error"] else HTTPException(422, first["error"])
    return {**first, "requires_approval": r["requires_approval"]}


@app.post("/v1/events/batch", tags=["store"], summary="Report up to 1,000 outcomes")
def report_batch(body: list[EventIn], actor: Actor = Depends(get_actor), s: Session = Depends(get_session)):
    if len(body) > 1000:
        raise HTTPException(413, "max 1000 events per batch")
    return workflow.submit(s, actor, [b.model_dump() for b in body], bulk=True)


@app.get("/v1/submissions", tags=["store"], summary="Entries waiting for approval (checkers) or your own entries (makers)")
def submissions(status: Literal["pending", "approved", "rejected", "all"] = "pending",
                actor: Actor = Depends(get_actor), s: Session = Depends(get_session)):
    return workflow.list_submissions(s, actor, status)


@app.post("/v1/submissions/approve", tags=["store"])
def approve(body: DecideIn, actor: Actor = Depends(get_actor), s: Session = Depends(get_session)):
    return workflow.decide(s, actor, body.ids[:500], True)


@app.post("/v1/submissions/reject", tags=["store"])
def reject(body: DecideIn, actor: Actor = Depends(get_actor), s: Session = Depends(get_session)):
    return workflow.decide(s, actor, body.ids[:500], False, body.reason)


@app.get("/v1/reports", tags=["store"], summary="Your store's activity plus network size, for the last N days")
def my_report(days: int = 30, actor: Actor = Depends(get_actor), s: Session = Depends(get_session)):
    actor.require("reports")
    m = actor.require_tenant()
    r = reports.build_report(s, days, merchant_id=m.id, countries=actor.countries)
    r["merchant"] = {"id": m.id, "name": m.name, "country": m.country}
    return r


@app.get("/v1/disputes", tags=["store"], summary="Open disputes that involve your store's records")
def my_disputes(actor: Actor = Depends(get_actor), s: Session = Depends(get_session)):
    return workflow.tenant_disputes(s, actor)


@app.post("/v1/disputes/{dispute_id}/respond", tags=["store"])
def respond(dispute_id: int, body: RespondIn, actor: Actor = Depends(get_actor), s: Session = Depends(get_session)):
    return workflow.respond_dispute(s, actor, dispute_id, body.action, body.note)


# ================================================================ store administration
def _tenant_scope(actor: Actor, merchant_id: int | None) -> int | None:
    """Which tenant's users this caller may manage. None = platform-level users."""
    if actor.is_platform:
        return merchant_id
    actor.require("users")
    return actor.require_tenant().id


@app.get("/v1/users", tags=["admin"])
def list_users(merchant_id: int | None = None, actor: Actor = Depends(get_actor), s: Session = Depends(get_session)):
    scope = _tenant_scope(actor, merchant_id)
    q = select(User).where(User.merchant_id == scope) if scope is not None else select(User).where(User.merchant_id.is_(None))
    return [auth.public_user(u) for u in s.scalars(q.order_by(User.created_at)).all()]


@app.post("/v1/users", tags=["admin"], status_code=201)
def add_user(body: UserIn, actor: Actor = Depends(get_actor), s: Session = Depends(get_session)):
    scope = _tenant_scope(actor, body.merchant_id)
    if body.is_platform_admin and not actor.is_platform:
        raise AuthError(403, "Only platform administrators can create platform administrators.")
    if body.is_platform_admin:
        scope = None
    elif scope is None:
        raise AuthError(422, "Choose which store this user belongs to.")
    m = s.get(Merchant, scope) if scope is not None else None
    if scope is not None and not m:
        raise AuthError(404, "Store not found.")
    if not actor.is_platform:
        bad = set(body.countries) - actor.countries
        if bad:
            raise AuthError(403, "You can only give access to countries you have yourself.")
    u, temp = auth.create_user(s, merchant=m, email=body.email, name=body.name, perms=body.perms,
                               countries=body.countries, is_platform_admin=body.is_platform_admin)
    audit(s, actor, "user.created", f"{u.email} perms={u.perms} countries={u.countries}", merchant_id=scope)
    return {"user": auth.public_user(u), "temporary_password": temp,
            "note": "Share the temporary password privately. The user must change it at first sign-in."}


@app.patch("/v1/users/{user_id}", tags=["admin"])
def edit_user(user_id: int, body: UserPatch, actor: Actor = Depends(get_actor), s: Session = Depends(get_session)):
    u = s.get(User, user_id)
    if not u:
        raise AuthError(404, "User not found.")
    if not actor.is_platform:
        actor.require("users")
        if u.merchant_id != actor.require_tenant().id:
            raise AuthError(404, "User not found.")
    me_ = actor.user and actor.user.id == u.id
    changes = []
    if body.name is not None:
        u.name = body.name.strip() or u.name; changes.append("name")
    if body.perms is not None and not u.is_platform_admin:
        if me_ and "users" not in body.perms:
            raise AuthError(422, "You can't remove your own user-admin access.")
        u.perms = auth.normalize_perms(body.perms); changes.append(f"perms={u.perms}")
    if body.countries is not None and not u.is_platform_admin:
        if not actor.is_platform and set(body.countries) - actor.countries:
            raise AuthError(403, "You can only give access to countries you have yourself.")
        u.countries = auth.normalize_countries(body.countries); changes.append(f"countries={u.countries}")
    if body.active is not None and body.active != u.active:
        if me_ and not body.active:
            raise AuthError(422, "You can't switch off your own account.")
        if body.active and u.merchant_id:
            auth.check_seat_available(s, s.get(Merchant, u.merchant_id))
        u.active = body.active; changes.append("activated" if body.active else "deactivated")
        if not body.active:
            auth.end_all_sessions(s, u.id)
    temp = None
    if body.reset_password:
        temp = auth.temp_password()
        u.password_hash, u.must_change_password = auth.hash_password(temp), True
        auth.end_all_sessions(s, u.id); changes.append("password reset")
    s.commit()
    audit(s, actor, "user.updated", f"{u.email}: {', '.join(changes) or 'no change'}", merchant_id=u.merchant_id)
    return {"user": auth.public_user(u), "temporary_password": temp}


@app.patch("/v1/tenant", tags=["admin"], summary="Store settings (user admins)")
def edit_tenant(body: TenantPatch, actor: Actor = Depends(get_actor), s: Session = Depends(get_session)):
    actor.require("users")
    m = s.get(Merchant, actor.require_tenant().id)
    if body.require_approval is not None:
        m.require_approval = body.require_approval
    s.commit()
    audit(s, actor, "tenant.updated", f"require_approval={m.require_approval}")
    return {"require_approval": m.require_approval}


@app.post("/v1/tenant/api-key", tags=["admin"], summary="Issue a new API key for system integrations (old key stops working)")
def rotate_key(actor: Actor = Depends(get_actor), s: Session = Depends(get_session)):
    actor.require("users")
    m = s.get(Merchant, actor.require_tenant().id)
    key = "cs_" + secrets.token_urlsafe(32)
    m.api_key_hash = service.hash_api_key(key)
    s.commit()
    audit(s, actor, "tenant.api_key_rotated")
    return {"api_key": key, "note": "Store this key now; it is not shown again."}


@app.get("/v1/audit", tags=["admin"])
def audit_log(limit: int = 200, merchant_id: int | None = None, actor: Actor = Depends(get_actor),
              s: Session = Depends(get_session)):
    q = select(AuditLog)
    if actor.is_platform:
        if merchant_id is not None:
            q = q.where(AuditLog.merchant_id == merchant_id)
    else:
        actor.require("users")
        q = q.where(AuditLog.merchant_id == actor.require_tenant().id)
    rows = s.scalars(q.order_by(AuditLog.created_at.desc()).limit(max(1, min(limit, 1000)))).all()
    names = {m.id: m.name for m in s.scalars(select(Merchant))} if actor.is_platform else {}
    return [{"at": r.created_at.isoformat(), "actor": r.actor, "action": r.action, "detail": r.detail,
             "store": names.get(r.merchant_id)} for r in rows]


# ================================================================ platform administration
def _merchant_view(s: Session, m: Merchant) -> dict:
    plan = PLANS.get(m.plan or "free", PLANS["free"])
    return {"id": m.id, "name": m.name, "country": m.country, "active": m.active,
            "agreement_signed": m.agreement_signed_at is not None, "trust_weight": m.trust_weight,
            "plan": m.plan or "free", "require_approval": m.require_approval,
            "seats_used": auth.seats_used(s, m.id), "seats_limit": plan["seats"],
            "checks_this_month": auth.checks_this_month(s, m.id), "checks_limit": plan["checks"]}


def _create_merchant(s: Session, actor: Actor, item: MerchantIn) -> dict:
    m, key = service.create_merchant(s, item.name, item.country, item.agreement_signed, item.feed_config)
    m.plan, m.require_approval = item.plan, item.require_approval
    s.commit()
    out = {"merchant_id": m.id, "name": m.name, "api_key": key}
    if item.admin_email:
        u, temp = auth.create_user(s, merchant=m, email=item.admin_email, name=item.admin_name or "",
                                   perms=ALL_PERMS, countries=["PK", "AE"])
        out["admin_user"] = {"email": u.email, "temporary_password": temp}
    audit(s, actor, "tenant.created", f"{m.name} ({m.country}, {m.plan})", merchant_id=m.id)
    return out


@app.post("/v1/admin/merchants", tags=["platform"])
def add_merchant(body: MerchantIn, actor: Actor = Depends(platform), s: Session = Depends(get_session)):
    try:
        out = _create_merchant(s, actor, body)
    except service.ValidationError as e:
        _bad(e)
    return {**out, "note": "Store this key now; it is not shown again."}


@app.post("/v1/admin/merchants/batch", tags=["platform"])
def add_merchants(body: list[MerchantIn], actor: Actor = Depends(platform), s: Session = Depends(get_session)):
    if len(body) > 200:
        raise HTTPException(413, "max 200 merchants per batch")
    out = []
    for i, item in enumerate(body):
        try:
            out.append({"index": i, "ok": True, **_create_merchant(s, actor, item)})
        except (service.ValidationError, AuthError) as e:
            s.rollback()
            out.append({"index": i, "ok": False, "name": item.name, "error": str(e)})
    return {"results": out, "note": "Store these keys now; they are not shown again."}


@app.get("/v1/admin/merchants", tags=["platform"])
def list_merchants(actor: Actor = Depends(platform), s: Session = Depends(get_session)):
    return [_merchant_view(s, m) for m in s.scalars(select(Merchant).order_by(Merchant.id)).all()]


@app.patch("/v1/admin/merchants/{merchant_id}", tags=["platform"])
def edit_merchant(merchant_id: int, body: MerchantPatch, actor: Actor = Depends(platform),
                  s: Session = Depends(get_session)):
    m = s.get(Merchant, merchant_id)
    if not m:
        raise AuthError(404, "Store not found.")
    if body.plan is not None:
        m.plan = body.plan
    if body.require_approval is not None:
        m.require_approval = body.require_approval
    if body.agreement_signed is not None:
        m.agreement_signed_at = (m.agreement_signed_at or utcnow()) if body.agreement_signed else None
    if body.active is not None:
        m.active = body.active
    s.commit()
    audit(s, actor, "tenant.updated", f"{m.name}: {body.model_dump(exclude_none=True)}", merchant_id=m.id)
    return _merchant_view(s, m)


@app.get("/v1/admin/reports", tags=["platform"])
def network_report(days: int = 30, actor: Actor = Depends(platform), s: Session = Depends(get_session)):
    return reports.build_report(s, days)


@app.get("/v1/admin/disputes", tags=["platform"])
def list_disputes(status: str = "open", actor: Actor = Depends(platform), s: Session = Depends(get_session)):
    rows = s.scalars(select(Dispute).where(Dispute.status == status).order_by(Dispute.created_at)).all()
    return [{"id": d.id, "reason": d.reason, "contact": d.contact, "status": d.status,
             "created_at": d.created_at.isoformat(), "store_responses": workflow.dispute_responses(s, d.id)}
            for d in rows]


@app.post("/v1/admin/disputes/{dispute_id}/resolve", tags=["platform"])
def resolve(dispute_id: int, body: ResolveIn, actor: Actor = Depends(platform), s: Session = Depends(get_session)):
    try:
        d = service.resolve_dispute(s, dispute_id, body.upheld, body.note)
    except service.ValidationError as e:
        _bad(e)
    audit(s, actor, "dispute.resolved", f"dispute #{d.id}: {d.status}" + (f" — {body.note}" if body.note else ""),
          merchant_id=None)
    return {"dispute_id": d.id, "status": d.status}


@app.get("/v1/admin/stats", tags=["platform"])
def stats(actor: Actor = Depends(platform), s: Session = Depends(get_session)):
    return {"merchants": s.scalar(select(func.count(Merchant.id))),
            "users": s.scalar(select(func.count(User.id)).where(User.active.is_(True))),
            "identities": s.scalar(select(func.count(Identity.id))),
            "events": s.scalar(select(func.count(Event.id))),
            "open_disputes": s.scalar(select(func.count(Dispute.id)).where(Dispute.status == "open"))}
