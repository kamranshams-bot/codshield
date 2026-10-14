"""Agents that keep the database up to date.

  python -m codshield.agents run            # one pass of all agents
  python -m codshield.agents run --loop     # keep running (default every hour)

Agents
  ingest       pulls each contributing merchant's feed, validates, de-duplicates
               and records events (merchants must have a signed agreement).
  maintenance  purges events past retention, escalates stale disputes,
               and down-weights merchants whose reports look abusive.
"""
import argparse
import logging
import time
from datetime import timedelta

from sqlalchemy import func, select
from sqlalchemy.orm.attributes import flag_modified

from .. import service
from ..config import settings
from ..db import SessionLocal, init_db
from ..models import (AgentRun, Dispute, Event, EventIdentity, EventStatus,
                      EventType, Identity, Merchant, utcnow)
from .connectors import CONNECTORS

log = logging.getLogger("codshield.agents")


def _start(s, agent, merchant_id=None) -> AgentRun:
    run = AgentRun(agent=agent, merchant_id=merchant_id)
    s.add(run)
    s.commit()
    return run


def _finish(s, run, stats=None, error=None):
    run.finished_at, run.stats, run.error = utcnow(), stats, error
    s.commit()


# ------------------------------------------------------------------ ingest
def ingest_merchant(s, m: Merchant) -> dict:
    cfg = dict(m.feed_config or {})
    connector = CONNECTORS.get(cfg.get("type"))
    if connector is None:
        return {"skipped": "no feed"}
    if m.agreement_signed_at is None:
        return {"skipped": "no signed agreement"}
    stats = {"created": 0, "duplicate": 0, "rejected": 0, "errors": []}
    new_cursor = None
    for item in connector(cfg):
        if "_cursor" in item:
            new_cursor = item["_cursor"]
            continue
        if "_error" in item:
            stats["rejected"] += 1
            stats["errors"].append(item["_error"])
            continue
        try:
            _, outcome = service.report_event(s, m, source=f"agent:{cfg['type']}", **item)
            stats[outcome] += 1
        except service.ValidationError as e:
            s.rollback()
            stats["rejected"] += 1
            stats["errors"].append(f"{item.get('order_ref')}: {e}")
    if new_cursor:
        cfg["cursor"] = new_cursor
        m.feed_config = cfg
        flag_modified(m, "feed_config")
        s.commit()
    stats["errors"] = stats["errors"][:50]
    return stats


def run_ingest(s) -> list[dict]:
    out = []
    for m in s.scalars(select(Merchant).where(Merchant.active.is_(True),
                                              Merchant.feed_config.is_not(None))).all():
        run = _start(s, "ingest", m.id)
        try:
            stats = ingest_merchant(s, m)
            _finish(s, run, stats)
        except Exception as e:  # one bad feed must not stop the others
            s.rollback()
            stats = {"error": str(e)}
            _finish(s, run, error=str(e))
        log.info("ingest merchant=%s %s", m.id, stats)
        out.append({"merchant_id": m.id, **stats})
    return out


# ------------------------------------------------------------- maintenance
ABUSE_MIN_REPORTS = 50
ABUSE_UPHELD_RATIO = 0.2     # >20% of a merchant's disputed reports overturned
STALE_DISPUTE_DAYS = 30


def run_maintenance(s) -> dict:
    run = _start(s, "maintenance")
    now = utcnow()
    stats = {}

    # 1. retention purge
    cutoff = now - timedelta(days=settings.RETENTION_DAYS)
    old_ids = s.scalars(select(Event.id).where(Event.occurred_at < cutoff)).all()
    if old_ids:
        s.query(EventIdentity).filter(EventIdentity.event_id.in_(old_ids)).delete(synchronize_session=False)
        s.query(Event).filter(Event.id.in_(old_ids)).delete(synchronize_session=False)
    # orphan identities (no events left)
    orphan = s.scalars(select(Identity.id).where(~Identity.id.in_(select(EventIdentity.identity_id)),
                                                 ~Identity.id.in_(select(Dispute.identity_id)))).all()
    if orphan:
        s.query(Identity).filter(Identity.id.in_(orphan)).delete(synchronize_session=False)
    stats["purged_events"], stats["purged_identities"] = len(old_ids), len(orphan)

    # 2. stale disputes -> flag for human review
    stale = s.scalars(select(Dispute).where(Dispute.status == "open",
                                            Dispute.created_at < now - timedelta(days=STALE_DISPUTE_DAYS))).all()
    stats["stale_disputes"] = [d.id for d in stale]

    # 3. merchant abuse detection: many removed (overturned) reports -> lower trust
    neg = [t.value for t in EventType if t != EventType.DELIVERED_PAID]
    rows = s.execute(select(Event.merchant_id, Event.status, func.count())
                     .where(Event.type.in_(neg)).group_by(Event.merchant_id, Event.status)).all()
    per = {}
    for mid, status, n in rows:
        per.setdefault(mid, {})[status] = n
    downgraded = []
    for mid, c in per.items():
        total = sum(c.values())
        removed = c.get(EventStatus.REMOVED.value, 0)
        if total >= ABUSE_MIN_REPORTS and removed / total > ABUSE_UPHELD_RATIO:
            m = s.get(Merchant, mid)
            if m.trust_weight > 0.5:
                m.trust_weight = 0.5
                downgraded.append(mid)
    stats["downgraded_merchants"] = downgraded

    s.commit()
    from .. import devapi
    stats["webhook_retries"] = devapi.retry_due(s)
    _finish(s, run, stats)
    log.info("maintenance %s", stats)
    return stats


def run_once() -> dict:
    init_db()
    with SessionLocal() as s:
        return {"ingest": run_ingest(s), "maintenance": run_maintenance(s)}


def main(argv=None):
    p = argparse.ArgumentParser(prog="codshield.agents")
    sub = p.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run")
    r.add_argument("--loop", action="store_true")
    r.add_argument("--interval", type=int, default=3600, help="seconds between passes")
    a = p.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")
    while True:
        print(run_once())
        if not a.loop:
            break
        time.sleep(a.interval)


if __name__ == "__main__":
    main()
