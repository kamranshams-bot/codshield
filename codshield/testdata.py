"""Remove synthetic test data (every outcome whose order_ref starts with TEST-).

    python -m codshield.testdata count     # how much test data is in the database
    python -m codshield.testdata purge     # delete it (asks for confirmation; add --yes to skip)

Uses the same database settings as the app (.env.local / .env / DATABASE_URL).
"""
import argparse

from sqlalchemy import select

from .db import SessionLocal, init_db
from .models import Dispute, Event, EventIdentity, Identity, Submission

PREFIX = "TEST-"


def _test_submissions(s):
    return [x for x in s.scalars(select(Submission)).all() if str((x.payload or {}).get("order_ref", "")).startswith(PREFIX)]


def count(s) -> dict:
    events = s.scalars(select(Event.id).where(Event.order_ref.like(PREFIX + "%"))).all()
    return {"events": len(events), "submissions": len(_test_submissions(s))}


def purge(s) -> dict:
    ids = s.scalars(select(Event.id).where(Event.order_ref.like(PREFIX + "%"))).all()
    for i in range(0, len(ids), 1000):
        chunk = ids[i:i + 1000]
        s.query(EventIdentity).filter(EventIdentity.event_id.in_(chunk)).delete(synchronize_session=False)
        s.query(Event).filter(Event.id.in_(chunk)).delete(synchronize_session=False)
    subs = _test_submissions(s)
    for x in subs:
        s.delete(x)
    s.flush()
    orphan = s.scalars(select(Identity.id).where(~Identity.id.in_(select(EventIdentity.identity_id)),
                                                 ~Identity.id.in_(select(Dispute.identity_id)))).all()
    for i in range(0, len(orphan), 1000):
        s.query(Identity).filter(Identity.id.in_(orphan[i:i + 1000])).delete(synchronize_session=False)
    s.commit()
    return {"events": len(ids), "submissions": len(subs), "identities": len(orphan)}


def main(argv=None):
    p = argparse.ArgumentParser(prog="codshield.testdata")
    p.add_argument("cmd", choices=["count", "purge"])
    p.add_argument("--yes", action="store_true", help="don't ask for confirmation")
    a = p.parse_args(argv)
    init_db()
    with SessionLocal() as s:
        found = count(s)
        print(f"Test data found: {found['events']} outcomes, {found['submissions']} entries")
        if a.cmd == "purge" and any(found.values()):
            if not a.yes and input("Delete it? Type yes: ").strip().lower() != "yes":
                print("Nothing deleted.")
                return
            print("Deleted:", purge(s))


if __name__ == "__main__":
    main()
