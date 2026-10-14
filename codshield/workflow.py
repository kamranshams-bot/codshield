"""Maker-checker workflow for outcomes, and store responses to consumer disputes."""
import secrets

from sqlalchemy import select
from sqlalchemy.orm import Session

from . import devapi, service
from .auth import Actor, AuthError, audit
from .models import (Dispute, DisputeResponse, Event, EventIdentity, EventStatus,
                     EventType, Identity, Merchant, Submission, User, utcnow)


def submit(s: Session, actor: Actor, items: list[dict], *, bulk: bool) -> dict:
    """Maker enters one or many outcomes. Pending until a checker approves (if the tenant requires it)."""
    m = actor.require_tenant()
    actor.require("upload" if bulk else "submit")
    batch_ref = ("B-" + secrets.token_hex(4).upper()) if bulk else None
    direct = not m.require_approval or actor.kind == "api_key"
    results = []
    for i, item in enumerate(items):
        try:
            country = (item.get("country") or m.country).upper()
            actor.require_country(country)
            prepared = service.prepare_event(m, **item)
        except (service.ValidationError, AuthError) as e:
            results.append({"index": i, "outcome": "rejected", "error": str(e)})
            continue
        if direct:
            ev, outcome = service.commit_event(s, m, prepared, source="ui" if actor.user else "api")
            results.append({"index": i, "outcome": outcome, "event_id": ev.id if ev else None})
            continue
        payload = {k: (v.isoformat() if hasattr(v, "isoformat") else v)
                   for k, v in prepared.items() if k not in ("identities", "contact_hint")}
        sub = Submission(merchant_id=m.id, maker_id=actor.user.id if actor.user else None, batch_ref=batch_ref,
                         country=prepared["country"], payload=payload, identities=prepared["identities"],
                         contact_hint=prepared["contact_hint"])
        s.add(sub)
        s.flush()
        results.append({"index": i, "outcome": "pending", "submission_id": sub.id})
    s.commit()
    n = lambda o: sum(1 for r in results if r["outcome"] == o)
    audit(s, actor, "outcomes.submit" if not direct else "outcomes.record",
          f"{len(items)} entries{' batch ' + batch_ref if batch_ref else ''}: "
          f"{n('pending')} pending, {n('created')} recorded, {n('duplicate')} duplicate, {n('rejected')} rejected")
    return {"batch_ref": batch_ref, "requires_approval": not direct, "results": results}


def _sub_view(s: Session, sub: Submission, names: dict) -> dict:
    return {"id": sub.id, "status": sub.status, "batch_ref": sub.batch_ref, "country": sub.country,
            "contact_hint": sub.contact_hint, **sub.payload,
            "maker": names.get(sub.maker_id, "API" if sub.maker_id is None else "?"), "maker_id": sub.maker_id,
            "checker": names.get(sub.checker_id), "reject_reason": sub.reject_reason,
            "created_at": sub.created_at.isoformat(), "decided_at": sub.decided_at.isoformat() if sub.decided_at else None}


def list_submissions(s: Session, actor: Actor, status: str = "pending", limit: int = 500) -> list[dict]:
    m = actor.require_tenant()
    if not ({"approve", "submit", "upload"} & actor.perms) and not actor.is_platform:
        raise AuthError(403, "Your role doesn't include access to entries.")
    q = select(Submission).where(Submission.merchant_id == m.id, Submission.country.in_(actor.countries))
    if status != "all":
        q = q.where(Submission.status == status)
    if "approve" not in actor.perms and actor.user:          # makers only see their own
        q = q.where(Submission.maker_id == actor.user.id)
    subs = s.scalars(q.order_by(Submission.created_at.desc()).limit(limit)).all()
    ids = {x for sub in subs for x in (sub.maker_id, sub.checker_id) if x}
    names = {u.id: u.name for u in s.scalars(select(User).where(User.id.in_(ids)))} if ids else {}
    return [_sub_view(s, sub, names) for sub in subs]


def decide(s: Session, actor: Actor, ids: list[int], approve: bool, reason: str | None = None) -> dict:
    m = actor.require_tenant()
    actor.require("approve")
    if not approve and not (reason or "").strip():
        raise AuthError(422, "Give a reason when rejecting, so the maker can fix the entry.")
    out = []
    for sid in ids:
        sub = s.get(Submission, sid)
        if not sub or sub.merchant_id != m.id:
            out.append({"id": sid, "ok": False, "error": "not found"}); continue
        if sub.status != "pending":
            out.append({"id": sid, "ok": False, "error": f"already {sub.status}"}); continue
        if sub.country not in actor.countries:
            out.append({"id": sid, "ok": False, "error": "outside your countries"}); continue
        if actor.user and sub.maker_id == actor.user.id:
            out.append({"id": sid, "ok": False, "error": "you entered this yourself; another checker must approve it"}); continue
        sub.checker_id = actor.user.id if actor.user else None
        sub.decided_at = utcnow()
        if approve:
            prepared = {**sub.payload, "identities": sub.identities}
            ev, outcome = service.commit_event(s, m, prepared, source="ui")
            sub = s.get(Submission, sid)                      # commit_event may have rolled back
            sub.status, sub.event_id = "approved", ev.id if ev else None
            sub.checker_id, sub.decided_at = actor.user.id if actor.user else None, utcnow()
            out.append({"id": sid, "ok": True, "outcome": outcome})
        else:
            sub.status, sub.reject_reason = "rejected", reason.strip()[:1000]
            out.append({"id": sid, "ok": True, "outcome": "rejected"})
        s.commit()
    done = [x["id"] for x in out if x["ok"]]
    if done:
        refs = {sub.id: sub.payload.get("order_ref") for sub in s.scalars(select(Submission).where(Submission.id.in_(done)))}
        devapi.emit(s, m.id, "entry.approved" if approve else "entry.rejected",
                    {"entries": [{"submission_id": i, "order_ref": refs.get(i)} for i in done],
                     **({} if approve else {"reason": reason})})
        audit(s, actor, "outcomes.approve" if approve else "outcomes.reject",
              f"{len(done)} entr{'y' if len(done) == 1 else 'ies'}: {', '.join('#' + str(i) for i in done[:50])}"
              + (f" — reason: {reason}" if not approve else ""))
    return {"results": out}


# ---------------------------------------------------------------- disputes (store side)
def _tenant_dispute_events(s: Session, dispute: Dispute, merchant_id: int) -> list[Event]:
    return s.scalars(select(Event).join(EventIdentity).where(
        EventIdentity.identity_id == dispute.identity_id, Event.merchant_id == merchant_id,
        Event.type != EventType.DELIVERED_PAID.value)).all()


def tenant_disputes(s: Session, actor: Actor) -> list[dict]:
    m = actor.require_tenant()
    actor.require("disputes")
    rows = s.scalars(select(Dispute).where(Dispute.status == "open").order_by(Dispute.created_at)).all()
    out = []
    for d in rows:
        evs = [e for e in _tenant_dispute_events(s, d, m.id) if e.country in actor.countries]
        if not evs:
            continue
        resp = s.scalar(select(DisputeResponse).where(DisputeResponse.dispute_id == d.id,
                                                      DisputeResponse.merchant_id == m.id)
                        .order_by(DisputeResponse.created_at.desc()))
        out.append({"id": d.id, "reason": d.reason, "created_at": d.created_at.isoformat(),
                    "your_records": [{"order_ref": e.order_ref, "type": e.type, "occurred_at": e.occurred_at.date().isoformat(),
                                      "evidence": e.evidence, "status": e.status} for e in evs],
                    "your_response": {"action": resp.action, "note": resp.note} if resp else None})
    return out


def respond_dispute(s: Session, actor: Actor, dispute_id: int, action: str, note: str | None) -> dict:
    m = actor.require_tenant()
    actor.require("disputes")
    if action not in ("withdraw", "confirm"):
        raise AuthError(422, "Choose withdraw or confirm.")
    d = s.get(Dispute, dispute_id)
    if not d or d.status != "open":
        raise AuthError(404, "Dispute not found or already decided.")
    evs = [e for e in _tenant_dispute_events(s, d, m.id) if e.country in actor.countries]
    if not evs:
        raise AuthError(404, "None of your records are part of this dispute.")
    if action == "withdraw":
        for e in evs:
            e.status = EventStatus.REMOVED.value
    s.add(DisputeResponse(dispute_id=d.id, merchant_id=m.id, user_id=actor.user.id if actor.user else None,
                          action=action, note=(note or "")[:2000]))
    s.commit()
    audit(s, actor, f"dispute.{action}", f"dispute #{d.id}, {len(evs)} record(s)" + (f": {note}" if note else ""))
    return {"dispute_id": d.id, "action": action, "records": len(evs)}


def dispute_responses(s: Session, dispute_id: int) -> list[dict]:
    rows = s.execute(select(DisputeResponse, Merchant.name).join(Merchant, Merchant.id == DisputeResponse.merchant_id)
                     .where(DisputeResponse.dispute_id == dispute_id).order_by(DisputeResponse.created_at)).all()
    return [{"store": n, "action": r.action, "note": r.note, "at": r.created_at.isoformat()} for r, n in rows]
