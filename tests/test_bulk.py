"""Bulk paths must give the same answers as the row-by-row ones."""
import json
from pathlib import Path

from tests.test_saas import add_user, c, new_tenant, outcome, uniq

from codshield import service
from codshield.db import SessionLocal

DATA = Path(__file__).resolve().parents[1] / "testdata" / "out"


def test_bulk_duplicates_and_identities():
    _, H, _ = new_tenant(approval=False)
    ref = uniq("BULK")
    body = [outcome(ref, "03001112233"), outcome(ref, "03001112233"),          # same order twice in one batch
            outcome(uniq("BULK"), "03001112233"), outcome("x", "1")]
    r = c.post("/v1/events/batch", headers=H, json=body).json()["results"]
    assert [x["outcome"] for x in r] == ["created", "duplicate", "created", "rejected"]
    again = c.post("/v1/events/batch", headers=H, json=body[:1]).json()["results"]
    assert again[0]["outcome"] == "duplicate"


def test_check_many_matches_single_checks():
    _, H, _ = new_tenant(approval=False)
    _, H2, _ = new_tenant(approval=False)
    rows = json.loads((DATA / "outcomes_batch1.json").read_text())[:300]
    tag = uniq("")
    for i, x in enumerate(rows):
        x["order_ref"] = f"{x['order_ref']}-{tag}"
    c.post("/v1/events/batch", headers=H, json=rows[:150])
    c.post("/v1/events/batch", headers=H2, json=rows[150:])
    people = [{k: x.get(k) for k in ("phone", "email", "address", "city", "country")} for x in rows[:60]]
    people.append({"phone": "123"})
    with SessionLocal() as s:
        bulk = service.check_many(s, people)
        for p, b in zip(people[:-1], bulk):
            single = service.check(s, **p)
            for k in ("score", "band", "reasons", "matched_on", "negative_events", "reporting_merchants"):
                assert single[k] == b[k], (k, p)
    assert "error" in bulk[-1]
    r = c.post("/v1/check/batch", headers=H, json=people).json()["results"]
    assert len(r) == 61 and r[-1]["ok"] is False and all(x["ok"] for x in r[:-1])


def test_bulk_approve_records_events():
    _, H, _ = new_tenant(approval=True)
    _, maker = add_user(H, ["submit", "upload"])
    _, checker = add_user(H, ["approve"])
    body = [outcome(uniq("AP"), "0300" + str(5000000 + i)) for i in range(40)]
    sub = c.post("/v1/events/batch", headers=maker, json=body).json()
    ids = [x["submission_id"] for x in sub["results"]]
    assert all(x["outcome"] == "pending" for x in sub["results"]) and len(set(ids)) == 40
    r = c.post("/v1/submissions/approve", headers=checker, json={"ids": ids}).json()["results"]
    assert all(x["ok"] and x["outcome"] == "created" for x in r)
    again = c.post("/v1/submissions/approve", headers=checker, json={"ids": ids[:2]}).json()["results"]
    assert all(not x["ok"] and "already approved" in x["error"] for x in again)
    own = c.post("/v1/submissions/approve", headers=maker, json={"ids": ids[:1]})
    assert own.status_code == 403 or not own.json()["results"][0]["ok"]
