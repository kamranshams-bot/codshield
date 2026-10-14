"""End-to-end check against the configured database (e.g. Neon).

    python verify_neon.py

Creates tables if needed, then runs: create merchants -> report events ->
risk check -> dispute -> resolve -> agents pass, and finally deletes every
row it created. Prints PASS/FAIL per step.
"""
import sys
import uuid
from datetime import timedelta

from sqlalchemy import delete, select, text

from codshield import service
from codshield.agents.runner import run_maintenance
from codshield.config import settings
from codshield.db import SessionLocal, engine, init_db
from codshield.models import (AgentRun, Dispute, Event, EventIdentity, Identity,
                              Merchant, utcnow)

ok = True


def step(name, cond, detail=""):
    global ok
    ok &= bool(cond)
    print(f"{'PASS' if cond else 'FAIL'}  {name}  {detail}")


url = engine.url
print(f"Database: {url.drivername}://{url.host}/{url.database}")
if url.drivername.startswith("sqlite"):
    print("FAIL  DATABASE_URL is not set; still using local SQLite. Run `neon deploy` first.")
    sys.exit(1)

with engine.connect() as c:
    version = c.execute(text("select version()")).scalar()
step("connect", version, version.split(",")[0])

init_db()
with engine.connect() as c:
    tables = set(c.execute(text(
        "select table_name from information_schema.tables where table_schema='public'")).scalars())
step("tables", {"merchants", "events", "identities", "disputes"} <= tables, ", ".join(sorted(tables)))

tag = "verify-" + uuid.uuid4().hex[:8]
phone = "0300" + str(uuid.uuid4().int)[:7]
merchant_ids = []
with SessionLocal() as s:
    try:
        m1, _ = service.create_merchant(s, f"{tag}-PK", "PK", agreement_signed=True)
        m2, _ = service.create_merchant(s, f"{tag}-AE", "AE", agreement_signed=True)
        merchant_ids = [m1.id, m2.id]
        step("create merchants", m1.id and m2.id, f"ids {m1.id}, {m2.id}")

        when = utcnow() - timedelta(days=2)
        _, o1 = service.report_event(s, m1, order_ref=f"{tag}-1", type="refused_at_door",
                                     occurred_at=when, phone=phone)
        _, o2 = service.report_event(s, m2, order_ref=f"{tag}-2", type="fake_order",
                                     occurred_at=when, phone="+92" + phone[1:], country="PK")
        _, o3 = service.report_event(s, m1, order_ref=f"{tag}-1", type="refused_at_door",
                                     occurred_at=when, phone=phone)
        step("report events + dedupe", (o1, o2, o3) == ("created", "created", "duplicate"), f"{o1}/{o2}/{o3}")

        r = service.check(s, phone=phone, country="PK")
        step("risk check (2 merchants, 2 formats)", r["reporting_merchants"] == 2 and r["score"] > 0,
             f"score={r['score']} band={r['band']}")

        d = service.open_dispute(s, phone=phone, country="PK", reason="verification run, not a real dispute", contact=None)
        frozen = service.check(s, phone=phone, country="PK")["score"]
        step("dispute freezes records", frozen == 0, f"score while disputed={frozen}")

        service.resolve_dispute(s, d.id, upheld=False, note="verification run")
        restored = service.check(s, phone=phone, country="PK")["score"]
        step("rejected dispute restores records", restored == r["score"], f"score={restored}")

        stats = run_maintenance(s)
        step("maintenance agent", "purged_events" in stats, str({k: stats[k] for k in ('purged_events', 'stale_disputes')}))

        stored = s.scalars(select(Identity.hash).join(EventIdentity).join(Event)
                           .where(Event.merchant_id == m1.id)).all()
        step("no raw phone stored", stored and all(phone[1:] not in h for h in stored), f"{len(stored)} hashed ids")
    except Exception as e:  # report and still clean up
        step("unexpected error", False, repr(e))
    finally:
        s.rollback()
        if merchant_ids:
            ev_ids = s.scalars(select(Event.id).where(Event.merchant_id.in_(merchant_ids))).all()
            id_ids = s.scalars(select(EventIdentity.identity_id).where(EventIdentity.event_id.in_(ev_ids))).all()
            s.execute(delete(EventIdentity).where(EventIdentity.event_id.in_(ev_ids)))
            s.execute(delete(Event).where(Event.id.in_(ev_ids)))
            s.execute(delete(Dispute).where(Dispute.identity_id.in_(id_ids)))
            still_used = s.scalars(select(EventIdentity.identity_id).where(EventIdentity.identity_id.in_(id_ids))).all()
            s.execute(delete(Identity).where(Identity.id.in_(set(id_ids) - set(still_used))))
            s.execute(delete(Merchant).where(Merchant.id.in_(merchant_ids)))
            s.execute(delete(AgentRun).where(AgentRun.started_at >= utcnow() - timedelta(minutes=10),
                                             AgentRun.agent == "maintenance"))
            s.commit()
            left = s.scalar(select(Merchant.id).where(Merchant.id.in_(merchant_ids)))
            step("cleanup", left is None, "test rows removed")

print("\nALL CHECKS PASSED" if ok else "\nSOME CHECKS FAILED")
sys.exit(0 if ok else 1)
