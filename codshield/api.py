"""CODShield HTTP API (multi-tenant SaaS).

Run:  uvicorn codshield.api:app --reload
Docs: http://localhost:8000/docs
"""
import logging
import os
import secrets
import time
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path
from typing import Literal

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.responses import HTMLResponse
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session
from sqlalchemy.exc import OperationalError as SQLAOperationalError
from sqlalchemy.exc import TimeoutError as SQLATimeoutError
from starlette.exceptions import HTTPException as StarletteHTTPException

from . import auth, devapi, reports, service, workflow
from .auth import Actor, AuthError, PLANS, audit
from .config import settings
from .db import get_session, init_db, pool_status

log = logging.getLogger("codshield")
if not log.handlers:                         # uvicorn only configures its own loggers
    _h = logging.StreamHandler()
    _h.setFormatter(logging.Formatter("%(levelname)s:    codshield %(message)s"))
    log.addHandler(_h)
    log.setLevel(logging.INFO)
    log.propagate = False
from .models import (ALL_PERMS, AuditLog, Dispute, Event, Identity, Merchant,
                     Submission, User, utcnow)

STATIC = Path(__file__).parent / "static"


async def _webhook_retry_loop():
    """Retry failed webhook deliveries every minute while the server is up."""
    import asyncio
    from starlette.concurrency import run_in_threadpool

    def tick():
        from .db import SessionLocal
        with SessionLocal() as s:
            return devapi.retry_due(s)
    while True:
        await asyncio.sleep(60)
        try:
            await run_in_threadpool(tick)
        except Exception:                     # never let the loop die
            log.exception("webhook retry tick failed")
        try:
            await run_in_threadpool(_log_pool_health)
        except Exception:
            log.exception("pool health check failed")


_pool_full_minutes = 0


def _log_pool_health():
    """Log the pool every minute; when it runs low, also log what each database connection is doing.
    If it stays completely full for two checks in a row, swap in a fresh pool so new requests work again."""
    global _pool_full_minutes
    from .db import IS_SQLITE, engine, pool_status
    st = pool_status()
    if not st:
        return
    log.info("db pool %s", st)
    full = st["checked_out"] >= st["size"] + 10
    _pool_full_minutes = _pool_full_minutes + 1 if full else 0
    if _pool_full_minutes >= 2:
        log.error("db pool stuck full for %d minutes; replacing it: %s", _pool_full_minutes, st)
        engine.dispose(close=False)      # stuck connections are abandoned, not waited for
        _pool_full_minutes = 0
        return
    if st["checked_out"] >= 8 and not IS_SQLITE:
        from sqlalchemy import text
        with engine.connect() as c:
            rows = c.execute(text(
                "SELECT state, wait_event_type, wait_event, now() - xact_start AS xact_age, "
                "now() - state_change AS state_age, left(query, 120) AS query FROM pg_stat_activity "
                "WHERE datname = current_database() AND pid <> pg_backend_pid() ORDER BY xact_start NULLS LAST")).all()
        for r in rows:
            log.warning("db activity %s", dict(r._mapping))


@asynccontextmanager
async def lifespan(_app):
    import asyncio
    init_db()
    task = asyncio.create_task(_webhook_retry_loop())
    yield
    task.cancel()


app = FastAPI(lifespan=lifespan, title="CODShield", version="0.3.0",
              description="Shared COD / return-abuse risk network for Pakistan and UAE merchants. "
                          "Stores hashed identifiers only. Multi-tenant with role-based access.")


ERROR_CODES = {400: "bad_request", 401: "unauthenticated", 402: "quota_exceeded", 403: "forbidden",
               404: "not_found", 405: "method_not_allowed", 409: "conflict", 413: "batch_too_large",
               422: "validation_failed", 429: "rate_limited", 503: "service_unavailable"}


def _error_code(status: int, message: str) -> str:
    m = message.lower()
    if status == 403:
        if "scope" in m:
            return "missing_scope"
        if "score-only" in m:
            return "tier_not_allowed"
        if "isn't set up for" in m:
            return "country_not_enabled"
        if "platform" in m:
            return "platform_only"
    if status == 401 and "session" in m:
        return "session_expired"
    if status == 401 and m.startswith("invalid") and "key" in m:
        return "invalid_api_key"
    return ERROR_CODES.get(status, "server_error" if status >= 500 else "error")


def error_response(request: Request, status: int, detail, headers: dict | None = None) -> JSONResponse:
    """One error shape everywhere. `detail` stays for existing clients; `error` adds a stable machine-readable code."""
    fields = None
    if isinstance(detail, list):        # pydantic validation errors: report all fields together
        fields = [{"field": ".".join(str(x) for x in e.get("loc", []) if x != "body"), "message": e.get("msg", "")}
                  for e in detail]
        message = "; ".join(f"{f['field']}: {f['message']}" for f in fields)
    else:
        message = str(detail)
    err = {"code": _error_code(status, message), "message": message, "status": status,
           "request_id": getattr(request.state, "request_id", None)}
    if fields:
        err["fields"] = fields
    return JSONResponse(status_code=status, content={"detail": detail, "error": err}, headers=headers)


@app.exception_handler(AuthError)
async def _auth_error(request: Request, exc: AuthError):
    return error_response(request, exc.status, str(exc))


@app.exception_handler(devapi.PlatformError)
async def _platform_error(request: Request, exc):
    return error_response(request, exc.status, str(exc))


@app.exception_handler(StarletteHTTPException)
async def _http_error(request: Request, exc: StarletteHTTPException):
    return error_response(request, exc.status_code, exc.detail, getattr(exc, "headers", None))


@app.exception_handler(SQLATimeoutError)
async def _pool_busy(request: Request, exc):
    log.error("database pool exhausted: %s", pool_status())
    return error_response(request, 503, "The service is busy. Try again in a few seconds.", {"Retry-After": "5"})


@app.exception_handler(SQLAOperationalError)
async def _db_unreachable(request: Request, exc):
    log.error("database unreachable: %s %s", type(exc.orig).__name__ if exc.orig else "", pool_status())
    return error_response(request, 503, "The database can't be reached right now. Try again in a few seconds.",
                          {"Retry-After": "5"})


@app.exception_handler(RequestValidationError)
async def _validation_error(request: Request, exc: RequestValidationError):
    return error_response(request, 422, jsonable_encoder(exc.errors()))


@app.middleware("http")
async def request_id_and_metering(request: Request, call_next):
    rid = (request.headers.get("x-request-id") or "req_" + secrets.token_hex(8))[:64]
    request.state.request_id = rid
    response = await call_next(request)
    response.headers["X-Request-ID"] = rid
    rate = getattr(request.state, "rate", None)
    if rate:
        response.headers["X-RateLimit-Limit"], response.headers["X-RateLimit-Remaining"], \
            response.headers["X-RateLimit-Reset"] = (str(v) for v in rate)
    meter = getattr(request.state, "meter", None)
    if meter:
        from starlette.concurrency import run_in_threadpool
        try:      # a blocking DB write on the event loop would stall every request; metering must never fail one
            await run_in_threadpool(_record_usage, meter, devapi.endpoint_label(request.method, request.url.path),
                                    response.status_code >= 400)
        except Exception:
            log.exception("usage metering failed")
    return response


def _record_usage(meter, label, error):
    from .db import SessionLocal
    with SessionLocal() as s:
        devapi.record_usage(s, meter[0], meter[1], label, error=error)


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
            return error_response(request, 503, "This CODShield server isn't set up yet: missing "
                                  + ", ".join(missing) + ".")
    return await call_next(request)


# ---------- rate limit ----------
_hits: dict[str, deque] = defaultdict(deque)


def _rate_limit(key: str, per_min: int | None = None, request: Request | None = None):
    """Sliding one-minute window. With `request`, the limit is announced in X-RateLimit-* headers."""
    now = time.time()
    limit = per_min or settings.RATE_LIMIT_PER_MIN
    q = _hits[key]
    while q and now - q[0] > 60:
        q.popleft()
    reset = int((q[0] + 60) if q else now + 60)
    if len(q) >= limit:
        if request is not None:
            request.state.rate = (limit, 0, reset)
        raise HTTPException(429, "Too many requests. Wait a minute and try again.",
                            headers={"Retry-After": str(max(1, int(reset - now)))})
    q.append(now)
    if request is not None:
        request.state.rate = (limit, limit - len(q), reset)


# ---------- who is calling ----------
def get_actor(request: Request, authorization: str | None = Header(None), x_api_key: str | None = Header(None),
              x_admin_key: str | None = Header(None), s: Session = Depends(get_session)) -> Actor:
    if authorization and authorization.lower().startswith("bearer "):
        u = auth.user_for_token(s, authorization[7:].strip())
        if not u:
            raise HTTPException(401, "Your session has ended. Sign in again.")
        a = auth.actor_for_user(s, u)
        _rate_limit(f"u{u.id}", request=request)
        return a
    if x_api_key:
        key = devapi.find_api_key(s, x_api_key)
        m = s.get(Merchant, key.merchant_id) if key else service.merchant_by_key(s, x_api_key)
        if m is None or not m.active:
            raise HTTPException(401, "invalid API key")
        a = auth.actor_for_api_key(m, key)
        if key is not None:
            key.last_used_at = utcnow()
            s.commit()
        request.state.meter = (m.id, a.api_key_id)
        _rate_limit(f"k{m.id}:{a.api_key_id}", devapi.PLAN_RATE.get(m.plan or "free", 60), request)
        return a
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
    tier: Literal["contributor", "score_only"] = "contributor"
    admin_email: str | None = None
    admin_name: str | None = None


class MerchantPatch(BaseModel):
    plan: PlanName | None = None
    tier: Literal["contributor", "score_only"] | None = None
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


class ApiKeyIn(BaseModel):
    name: str = Field(..., min_length=1, max_length=80)
    mode: Literal["live", "test"] = "live"
    scopes: list[Literal["check", "report", "read"]] = ["check"]


class WebhookIn(BaseModel):
    url: str = Field(..., max_length=500)
    events: list[str]


class WebhookPatch(BaseModel):
    active: bool | None = None
    events: list[str] | None = None


# ================================================================ public
@app.get("/", include_in_schema=False)
def home():
    return FileResponse(STATIC / "index.html")


@app.get("/health")
def health():
    """Liveness plus a real database round trip, so a platform health check can restart a stuck server."""
    from sqlalchemy import text
    from .db import engine
    try:
        with engine.connect() as c:
            c.execute(text("SELECT 1"))
        return {"ok": True, "db": "ok", "pool": pool_status()}
    except Exception as e:
        log.error("health check failed: %s %s", type(e).__name__, pool_status())
        return JSONResponse(status_code=503, content={"ok": False, "db": type(e).__name__, "pool": pool_status()})


@app.get("/v1/meta", tags=["public"])
def meta(s: Session = Depends(get_session)):
    """What the sign-in screen needs to know."""
    has_admin = s.scalar(select(func.count(User.id)).where(User.is_platform_admin.is_(True))) > 0
    return {"setup_required": not has_admin, "permissions": ALL_PERMS, "plans": PLANS,
            "api": {"scopes": devapi.SCOPES, "tiers": devapi.TIERS, "webhook_events": devapi.WEBHOOK_EVENTS,
                    "rate_limits_per_minute": devapi.PLAN_RATE,
                    "sandbox_numbers": {k: {"band": v[0], "score": v[1]} for k, v in devapi.SANDBOX_NUMBERS.items()}}}


@app.get("/developers", include_in_schema=False, response_class=HTMLResponse)
def developers():
    return FileResponse(STATIC / "developers.html")


@app.post("/v1/disputes", tags=["public"], summary="A consumer contests records linked to their phone number")
def create_dispute(body: DisputeIn, s: Session = Depends(get_session)):
    _rate_limit("disputes")
    try:
        d = service.open_dispute(s, phone=body.phone, country=body.country, reason=body.reason, contact=body.contact)
    except service.ValidationError as e:
        _bad(e)
    audit(s, None, "dispute.opened", f"dispute #{d.id}", merchant_id=None)
    _notify_dispute(s, d, "dispute.opened")
    return {"dispute_id": d.id, "status": d.status, "message": "Records are excluded from scoring while we review."}


def _notify_dispute(s: Session, d: Dispute, event: str) -> None:
    from .models import EventIdentity
    rows = s.execute(select(Event.merchant_id, Event.order_ref, Event.type).join(EventIdentity)
                     .where(EventIdentity.identity_id == d.identity_id)).all()
    per = {}
    for mid, ref, typ in rows:
        per.setdefault(mid, []).append({"order_ref": ref, "type": typ})
    for mid, recs in per.items():
        devapi.emit(s, mid, event, {"dispute_id": d.id, "status": d.status, "your_records": recs})


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
                         "agreement_signed": m.agreement_signed_at is not None,
                         "tier": m.tier or "contributor", "tier_label": devapi.TIERS.get(m.tier or "contributor")}
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
def _run_check(s: Session, actor: Actor, item: CheckIn) -> dict:
    actor.require_country(item.country)
    if actor.mode == "test":
        return devapi.sandbox_check(item.phone, item.email, item.country)
    r = service.check(s, merchant=actor.merchant, **item.model_dump())
    if actor.merchant is not None and (actor.merchant.tier or "contributor") == "score_only":
        r = devapi.score_only_view(r)
    return r


def _quota_warning(s: Session, m: Merchant | None, before: int, n: int) -> None:
    if m is None:
        return
    limit = PLANS.get(m.plan or "free", PLANS["free"])["checks"]
    if limit and before < int(limit * 0.8) <= before + n:
        devapi.emit(s, m.id, "quota.warning", {"checks_this_month": before + n, "monthly_limit": limit,
                                               "plan": m.plan or "free"})


@app.post("/v1/check", tags=["store"])
def check(body: CheckIn, actor: Actor = Depends(get_actor), s: Session = Depends(get_session)):
    actor.require("check")
    before = 0
    if actor.merchant and actor.mode == "live":
        auth.check_quota(s, actor.merchant)
        before = auth.checks_this_month(s, actor.merchant.id)
    try:
        r = _run_check(s, actor, body)
    except (service.ValidationError, devapi.PlatformError) as e:
        _bad(e)
    if actor.mode == "live":
        _quota_warning(s, actor.merchant, before, 1)
    return r


@app.post("/v1/check/batch", tags=["store"], summary="Check up to 500 orders in one call")
def check_batch(body: list[CheckIn], actor: Actor = Depends(get_actor), s: Session = Depends(get_session)):
    actor.require("check")
    if len(body) > 500:
        raise HTTPException(413, "max 500 orders per batch")
    before = 0
    if actor.merchant and actor.mode == "live":
        auth.check_quota(s, actor.merchant, len(body))
        before = auth.checks_this_month(s, actor.merchant.id)
    results = []
    for i, item in enumerate(body):
        try:
            results.append({"index": i, "ok": True, **_run_check(s, actor, item)})
        except (service.ValidationError, AuthError, devapi.PlatformError) as e:
            results.append({"index": i, "ok": False, "error": str(e)})
    if actor.mode == "live":
        _quota_warning(s, actor.merchant, before, sum(1 for r in results if r["ok"]))
    return {"results": results}


@app.post("/v1/events", tags=["store"], status_code=201,
          summary="Report one outcome (API keys record directly; users go through approval if required)")
def report(body: EventIn, actor: Actor = Depends(get_actor), s: Session = Depends(get_session)):
    if actor.mode == "test":
        actor.require("submit")
        return _sandbox_events(actor, [body.model_dump()])["results"][0] | {"requires_approval": False}
    r = workflow.submit(s, actor, [body.model_dump()], bulk=False)
    first = r["results"][0]
    if first["outcome"] == "rejected":
        raise AuthError(403, first["error"]) if "isn't set up for" in first["error"] else HTTPException(422, first["error"])
    return {**first, "requires_approval": r["requires_approval"]}


@app.post("/v1/events/batch", tags=["store"], summary="Report up to 1,000 outcomes")
def report_batch(body: list[EventIn], actor: Actor = Depends(get_actor), s: Session = Depends(get_session)):
    if len(body) > 1000:
        raise HTTPException(413, "max 1000 events per batch")
    if actor.mode == "test":
        actor.require("upload")
        return _sandbox_events(actor, [b.model_dump() for b in body])
    return workflow.submit(s, actor, [b.model_dump() for b in body], bulk=True)


def _sandbox_events(actor: Actor, items: list[dict]) -> dict:
    """Test mode: validate exactly as live, store nothing."""
    out = []
    for i, it in enumerate(items):
        try:
            actor.require_country((it.get("country") or actor.merchant.country).upper())
            service.prepare_event(actor.merchant, **it)
            out.append({"index": i, "outcome": "test_accepted", "test_mode": True})
        except (service.ValidationError, AuthError) as e:
            out.append({"index": i, "outcome": "rejected", "error": str(e), "test_mode": True})
    if len(items) == 1 and out[0]["outcome"] == "rejected":
        raise HTTPException(422, out[0]["error"])
    return {"batch_ref": None, "requires_approval": False, "results": out, "test_mode": True}


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


# ================================================================ developer API platform
def _key_admin(actor: Actor) -> Merchant:
    actor.require("users")
    return actor.require_tenant()


@app.get("/v1/api-keys", tags=["developers"])
def list_keys(actor: Actor = Depends(get_actor), s: Session = Depends(get_session)):
    m = _key_admin(actor)
    from .models import ApiKey
    return [devapi.key_view(k) for k in s.scalars(select(ApiKey).where(ApiKey.merchant_id == m.id)
                                                   .order_by(ApiKey.revoked_at.is_not(None), ApiKey.created_at.desc())).all()]


@app.post("/v1/api-keys", tags=["developers"], status_code=201)
def new_key(body: ApiKeyIn, actor: Actor = Depends(get_actor), s: Session = Depends(get_session)):
    m = _key_admin(actor)
    k, raw = devapi.create_api_key(s, m, name=body.name, mode=body.mode, scopes=body.scopes,
                                   created_by=actor.user.id if actor.user else None)
    audit(s, actor, "api_key.created", f"{k.name} ({k.prefix}…, {k.mode}, scopes={k.scopes})")
    return {"key": devapi.key_view(k), "api_key": raw, "note": "Store this key now; it is not shown again."}


@app.delete("/v1/api-keys/{key_id}", tags=["developers"])
def revoke_key(key_id: int, actor: Actor = Depends(get_actor), s: Session = Depends(get_session)):
    m = _key_admin(actor)
    from .models import ApiKey
    k = s.get(ApiKey, key_id)
    if not k or k.merchant_id != m.id:
        raise AuthError(404, "Key not found.")
    if k.revoked_at is None:
        k.revoked_at = utcnow()
        s.commit()
        audit(s, actor, "api_key.revoked", f"{k.name} ({k.prefix}…)")
    return devapi.key_view(k)


@app.get("/v1/usage", tags=["developers"], summary="API calls per day, key and endpoint")
def usage(days: int = 30, actor: Actor = Depends(get_actor), s: Session = Depends(get_session)):
    m = actor.require_tenant()
    if "users" not in actor.perms and "reports" not in actor.perms:
        raise AuthError(403, "You need user-admin access or the read scope to see usage.")
    return devapi.usage_report(s, m.id, days)


@app.get("/v1/webhooks", tags=["developers"])
def list_webhooks(actor: Actor = Depends(get_actor), s: Session = Depends(get_session)):
    m = _key_admin(actor)
    from .models import WebhookEndpoint
    eps = s.scalars(select(WebhookEndpoint).where(WebhookEndpoint.merchant_id == m.id)
                    .order_by(WebhookEndpoint.created_at.desc())).all()
    return {"events": devapi.WEBHOOK_EVENTS, "endpoints": [devapi.endpoint_view(e, s) for e in eps]}


@app.post("/v1/webhooks", tags=["developers"], status_code=201)
def add_webhook(body: WebhookIn, actor: Actor = Depends(get_actor), s: Session = Depends(get_session)):
    m = _key_admin(actor)
    ep, secret = devapi.create_endpoint(s, m, body.url, body.events)
    audit(s, actor, "webhook.created", f"{ep.url} events={ep.events}")
    return {"endpoint": devapi.endpoint_view(ep, s), "signing_secret": secret,
            "note": "Use this secret to verify the X-CODShield-Signature header. It is not shown again."}


@app.patch("/v1/webhooks/{endpoint_id}", tags=["developers"])
def edit_webhook(endpoint_id: int, body: WebhookPatch, actor: Actor = Depends(get_actor), s: Session = Depends(get_session)):
    m = _key_admin(actor)
    from .models import WebhookEndpoint
    ep = s.get(WebhookEndpoint, endpoint_id)
    if not ep or ep.merchant_id != m.id:
        raise AuthError(404, "Webhook not found.")
    if body.events is not None:
        ev = [e for e in body.events if e in devapi.WEBHOOK_EVENTS]
        if not ev:
            raise AuthError(422, "Choose at least one event.")
        ep.events = ",".join(ev)
    if body.active is not None:
        ep.active = body.active
    s.commit()
    audit(s, actor, "webhook.updated", f"{ep.url}: active={ep.active} events={ep.events}")
    return devapi.endpoint_view(ep, s)


@app.post("/v1/webhooks/{endpoint_id}/test", tags=["developers"], summary="Send a ping event now")
def ping_webhook(endpoint_id: int, actor: Actor = Depends(get_actor), s: Session = Depends(get_session)):
    m = _key_admin(actor)
    from .models import WebhookDelivery, WebhookEndpoint
    ep = s.get(WebhookEndpoint, endpoint_id)
    if not ep or ep.merchant_id != m.id or not ep.active:
        raise AuthError(404, "Webhook not found or switched off.")
    d = WebhookDelivery(endpoint_id=ep.id, event_id="evt_test_" + secrets.token_hex(6), event="ping",
                        payload={"id": "evt_test", "type": "ping", "created_at": utcnow().isoformat() + "Z",
                                 "data": {"message": "Hello from CODShield"}})
    s.add(d)
    s.commit()
    status = devapi.deliver(d.id)
    s.expire_all()
    d = s.get(WebhookDelivery, d.id)
    return {"status": status, "response_code": d.response_code, "error": d.last_error}


# ================================================================ platform administration
def _merchant_view(s: Session, m: Merchant) -> dict:
    plan = PLANS.get(m.plan or "free", PLANS["free"])
    return {"id": m.id, "name": m.name, "country": m.country, "active": m.active,
            "agreement_signed": m.agreement_signed_at is not None, "trust_weight": m.trust_weight,
            "plan": m.plan or "free", "require_approval": m.require_approval, "tier": m.tier or "contributor",
            "seats_used": auth.seats_used(s, m.id), "seats_limit": plan["seats"],
            "checks_this_month": auth.checks_this_month(s, m.id), "checks_limit": plan["checks"]}


def _create_merchant(s: Session, actor: Actor, item: MerchantIn) -> dict:
    m, key = service.create_merchant(s, item.name, item.country, item.agreement_signed, item.feed_config)
    m.plan, m.require_approval, m.tier = item.plan, item.require_approval, item.tier
    s.commit()
    out = {"merchant_id": m.id, "name": m.name, "api_key": key}
    if item.admin_email:
        u, temp = auth.create_user(s, merchant=m, email=item.admin_email, name=item.admin_name or "",
                                   perms=ALL_PERMS, countries=["PK", "AE"])
        out["admin_user"] = {"email": u.email, "temporary_password": temp}
    audit(s, actor, "tenant.created", f"{m.name} ({m.country}, {m.plan})", merchant_id=m.id)
    return out


@app.post("/v1/admin/merchants", tags=["platform"], status_code=201)
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
    if body.tier is not None:
        m.tier = body.tier
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
    _notify_dispute(s, d, "dispute.resolved")
    return {"dispute_id": d.id, "status": d.status}


@app.get("/v1/admin/stats", tags=["platform"])
def stats(actor: Actor = Depends(platform), s: Session = Depends(get_session)):
    return {"merchants": s.scalar(select(func.count(Merchant.id))),
            "users": s.scalar(select(func.count(User.id)).where(User.active.is_(True))),
            "identities": s.scalar(select(func.count(Identity.id))),
            "events": s.scalar(select(func.count(Event.id))),
            "open_disputes": s.scalar(select(func.count(Dispute.id)).where(Dispute.status == "open"))}


# ================================================================ OpenAPI contract
PUBLIC_OPS = {("get", "/health"), ("get", "/v1/meta"), ("post", "/v1/disputes"), ("post", "/v1/auth/login")}
_RATE_HEADERS = {
    "X-Request-ID": {"description": "Quote this to support.", "schema": {"type": "string"}},
    "X-RateLimit-Limit": {"description": "Requests allowed per minute for this key (API keys).", "schema": {"type": "integer"}},
    "X-RateLimit-Remaining": {"description": "Requests left in the current minute.", "schema": {"type": "integer"}},
    "X-RateLimit-Reset": {"description": "Unix time when the window frees up.", "schema": {"type": "integer"}},
}


def _error_response(desc: str, code: str, msg: str, status: int, extra_headers=None) -> dict:
    r = {"description": desc, "content": {"application/json": {
        "schema": {"$ref": "#/components/schemas/ErrorResponse"},
        "example": {"detail": msg, "error": {"code": code, "message": msg, "status": status,
                                              "request_id": "req_2548d6f3f1575c5a"}}}}}
    if extra_headers:
        r["headers"] = extra_headers
    return r


def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    from fastapi.openapi.utils import get_openapi
    spec = get_openapi(title="CODShield API", version=app.version, routes=app.routes, description=(
        "Check a cash-on-delivery customer's risk before shipping, and report delivery outcomes afterwards "
        "(Pakistan and UAE).\n\nAuthentication: system integrations send `X-API-Key` (scopes check / report / read; "
        "`cs_test_` keys run in a sandbox). People sign in with `POST /v1/auth/login` and send the session token as "
        "`Authorization: Bearer`. Platform operators use `X-Admin-Key`. Store admins create API keys in the web app "
        "(Developers) or with `POST /v1/api-keys`.\n\nErrors share one shape: branch on `error.code`. Batches: up to "
        "500 checks or 1,000 outcomes per call; rows fail one by one. Retrying an outcome is safe (stored once per "
        "store, order_ref and type).\n\nGuide and data dictionary: /developers"))
    spec["servers"] = [{"url": "https://codshield-sx1i.onrender.com", "description": "Production"}]
    comps = spec.setdefault("components", {})
    comps["securitySchemes"] = {
        "ApiKey": {"type": "apiKey", "in": "header", "name": "X-API-Key",
                   "description": "Store API key (cs_live_ / cs_test_), created by a store admin."},
        "Session": {"type": "http", "scheme": "bearer", "description": "Session token from POST /v1/auth/login (12 hours)."},
        "AdminKey": {"type": "apiKey", "in": "header", "name": "X-Admin-Key", "description": "Platform operators only."},
    }
    comps.setdefault("schemas", {})["ErrorResponse"] = {
        "type": "object", "required": ["error"],
        "properties": {
            "detail": {"description": "Kept for older integrations: the message, or the list of validation errors."},
            "error": {"type": "object", "required": ["code", "message", "status"], "properties": {
                "code": {"type": "string", "description": (
                    "Stable machine-readable code. Handling: unauthenticated / invalid_api_key / session_expired -> "
                    "fix credentials or sign in again, don't retry; missing_scope / tier_not_allowed / "
                    "country_not_enabled / forbidden / platform_only -> use a key or user with that access, don't retry; "
                    "validation_failed -> fix error.fields, don't retry unchanged; quota_exceeded -> upgrade the plan, "
                    "retry next month; batch_too_large -> split the batch; rate_limited -> wait Retry-After seconds "
                    "then retry; service_unavailable / server_error -> retry with backoff; not_found / conflict -> "
                    "check the ID or use the existing record."),
                         "enum": sorted(set(ERROR_CODES.values()) | {"missing_scope", "tier_not_allowed",
                                        "country_not_enabled", "platform_only", "session_expired",
                                        "invalid_api_key", "server_error"})},
                "message": {"type": "string", "description": "Plain-language explanation."},
                "status": {"type": "integer"},
                "request_id": {"type": "string", "description": "Same as the X-Request-ID header."},
                "fields": {"type": "array", "description": "422 only: every invalid field.", "items": {
                    "type": "object", "properties": {"field": {"type": "string"}, "message": {"type": "string"}}}},
            }},
        }}
    common = {
        "401": _error_response("Missing, wrong or revoked credentials", "unauthenticated", "Sign in, or send an API key.", 401),
        "403": _error_response("Not allowed for this key, user, tier or country", "missing_scope",
                               "This API key doesn't have the 'report' scope.", 403),
        "429": _error_response("Rate limit reached", "rate_limited", "Too many requests. Wait a minute and try again.", 429,
                               {"Retry-After": {"description": "Seconds to wait.", "schema": {"type": "integer"}}}),
    }
    for path, ops in spec["paths"].items():
        for method, op in ops.items():
            public = (method, path) in PUBLIC_OPS
            tags = op.get("tags", [])
            if public:
                op["security"] = []
            elif "platform" in tags:
                op["security"] = [{"AdminKey": []}, {"Session": []}]
            elif tags and tags[0] in ("auth", "admin", "developers") and path not in ("/v1/usage",):
                op["security"] = [{"Session": []}]
            else:
                op["security"] = [{"ApiKey": []}, {"Session": []}]
            # header params duplicated by the security schemes add noise
            op["parameters"] = [p for p in op.get("parameters", [])
                                if not (p.get("in") == "header" and p["name"].lower() in ("authorization", "x-api-key", "x-admin-key"))]
            if not op["parameters"]:
                op.pop("parameters")
            resp = op.setdefault("responses", {})
            for code, r in resp.items():
                if code.startswith("2"):
                    r.setdefault("headers", {}).update(_RATE_HEADERS)
            if "422" in resp:
                resp["422"] = _error_response("Validation failed; error.fields lists every invalid field",
                                              "validation_failed", "country: Input should be 'PK' or 'AE'", 422)
            if not public:
                for code, r in common.items():
                    resp.setdefault(code, r)
            else:
                resp.setdefault("429", common["429"])
    if "/v1/check" in spec["paths"]:
        spec["paths"]["/v1/check"]["post"].setdefault("responses", {})["402"] = _error_response(
            "Monthly check quota used up", "quota_exceeded", "This month's 1,000 order checks on the Free plan are used up.", 402)
    for p in ("/v1/check/batch", "/v1/events/batch"):
        if p in spec["paths"]:
            spec["paths"][p]["post"]["responses"]["413"] = _error_response(
                "Batch too large", "batch_too_large", "max 500 orders per batch", 413)
    app.openapi_schema = spec
    return spec


app.openapi = custom_openapi
