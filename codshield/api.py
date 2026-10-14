"""CODShield HTTP API.

Run:  uvicorn codshield.api:app --reload
Docs: http://localhost:8000/docs
"""
import time
from contextlib import asynccontextmanager
from collections import defaultdict, deque
from datetime import datetime
from typing import Literal

from pathlib import Path

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from . import service
from .config import settings
from .db import get_session, init_db
from .models import Dispute, Event, Identity, Merchant

STATIC = Path(__file__).parent / "static"

@asynccontextmanager
async def lifespan(_app):
    init_db()
    yield


app = FastAPI(lifespan=lifespan, title="CODShield", version="0.1.0",
              description="Shared COD / return-abuse risk network for Pakistan and UAE merchants. "
                          "Stores hashed identifiers only.")


# ---------- auth & rate limit ----------
_hits: dict[str, deque] = defaultdict(deque)


def _rate_limit(key: str):
    now = time.time()
    q = _hits[key]
    while q and now - q[0] > 60:
        q.popleft()
    if len(q) >= settings.RATE_LIMIT_PER_MIN:
        raise HTTPException(429, "rate limit exceeded")
    q.append(now)


def merchant_auth(x_api_key: str = Header(...), s: Session = Depends(get_session)) -> Merchant:
    m = service.merchant_by_key(s, x_api_key)
    if m is None:
        raise HTTPException(401, "invalid API key")
    _rate_limit(f"m{m.id}")
    return m


def admin_auth(x_admin_key: str = Header(...)):
    if x_admin_key != settings.ADMIN_KEY:
        raise HTTPException(401, "invalid admin key")


def _bad(e: Exception):
    raise HTTPException(422, str(e))


# ---------- schemas ----------
Country = Literal["PK", "AE"]


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


class ResolveIn(BaseModel):
    upheld: bool
    note: str | None = None


# ---------- public ----------
@app.get("/", include_in_schema=False)
def home():
    return FileResponse(STATIC / "index.html")


@app.get("/health")
def health():
    return {"ok": True}


@app.post("/v1/disputes", tags=["public"],
          summary="A consumer contests records linked to their phone number")
def create_dispute(body: DisputeIn, s: Session = Depends(get_session)):
    _rate_limit("disputes")
    try:
        d = service.open_dispute(s, phone=body.phone, country=body.country,
                                 reason=body.reason, contact=body.contact)
    except service.ValidationError as e:
        _bad(e)
    return {"dispute_id": d.id, "status": d.status,
            "message": "Records are excluded from scoring while we review."}


# ---------- merchant ----------
@app.post("/v1/check", tags=["merchant"])
def check(body: CheckIn, m: Merchant = Depends(merchant_auth), s: Session = Depends(get_session)):
    try:
        return service.check(s, **body.model_dump())
    except service.ValidationError as e:
        _bad(e)


@app.post("/v1/events", tags=["merchant"], status_code=201)
def report(body: EventIn, m: Merchant = Depends(merchant_auth), s: Session = Depends(get_session)):
    try:
        ev, outcome = service.report_event(s, m, **body.model_dump())
    except service.ValidationError as e:
        _bad(e)
    return {"event_id": ev.id if ev else None, "outcome": outcome}


@app.post("/v1/events/batch", tags=["merchant"])
def report_batch(body: list[EventIn], m: Merchant = Depends(merchant_auth),
                 s: Session = Depends(get_session)):
    if len(body) > 1000:
        raise HTTPException(413, "max 1000 events per batch")
    results = []
    for i, item in enumerate(body):
        try:
            ev, outcome = service.report_event(s, m, **item.model_dump())
            results.append({"index": i, "outcome": outcome, "event_id": ev.id if ev else None})
        except service.ValidationError as e:
            s.rollback()
            results.append({"index": i, "outcome": "rejected", "error": str(e)})
    return {"results": results}


# ---------- admin ----------
@app.post("/v1/admin/merchants", tags=["admin"], dependencies=[Depends(admin_auth)])
def add_merchant(body: MerchantIn, s: Session = Depends(get_session)):
    try:
        m, key = service.create_merchant(s, body.name, body.country, body.agreement_signed,
                                         body.feed_config)
    except service.ValidationError as e:
        _bad(e)
    return {"merchant_id": m.id, "api_key": key, "note": "Store this key now; it is not shown again."}


@app.get("/v1/admin/disputes", tags=["admin"], dependencies=[Depends(admin_auth)])
def list_disputes(status: str = "open", s: Session = Depends(get_session)):
    rows = s.scalars(select(Dispute).where(Dispute.status == status).order_by(Dispute.created_at)).all()
    return [{"id": d.id, "reason": d.reason, "contact": d.contact, "status": d.status,
             "created_at": d.created_at.isoformat()} for d in rows]


@app.post("/v1/admin/disputes/{dispute_id}/resolve", tags=["admin"], dependencies=[Depends(admin_auth)])
def resolve(dispute_id: int, body: ResolveIn, s: Session = Depends(get_session)):
    try:
        d = service.resolve_dispute(s, dispute_id, body.upheld, body.note)
    except service.ValidationError as e:
        _bad(e)
    return {"dispute_id": d.id, "status": d.status}


@app.get("/v1/admin/merchants", tags=["admin"], dependencies=[Depends(admin_auth)])
def list_merchants(s: Session = Depends(get_session)):
    return [{"id": m.id, "name": m.name, "country": m.country, "active": m.active,
             "agreement_signed": m.agreement_signed_at is not None, "trust_weight": m.trust_weight}
            for m in s.scalars(select(Merchant).order_by(Merchant.id)).all()]


@app.get("/v1/admin/stats", tags=["admin"], dependencies=[Depends(admin_auth)])
def stats(s: Session = Depends(get_session)):
    return {"merchants": s.scalar(select(func.count(Merchant.id))),
            "identities": s.scalar(select(func.count(Identity.id))),
            "events": s.scalar(select(func.count(Event.id))),
            "open_disputes": s.scalar(select(func.count(Dispute.id)).where(Dispute.status == "open"))}
