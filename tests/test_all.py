import os
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

_tmp = tempfile.mkdtemp()
os.environ["CODSHIELD_DATABASE_URL"] = f"sqlite:///{_tmp}/test.db"
os.environ["CODSHIELD_HASH_SECRET"] = "test-secret"
os.environ["CODSHIELD_ADMIN_KEY"] = "adm"

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from codshield.api import app  # noqa: E402
from codshield.db import SessionLocal, init_db  # noqa: E402
from codshield.identity import normalize_email, normalize_phone  # noqa: E402
from codshield.models import Event, Merchant  # noqa: E402

init_db()
client = TestClient(app)
ADM = {"X-Admin-Key": "adm"}
NOW = datetime.now(timezone.utc).replace(tzinfo=None)


def iso(days_ago=1):
    return (NOW - timedelta(days=days_ago)).isoformat()


def new_merchant(name, country="PK", signed=True, feed=None):
    r = client.post("/v1/admin/merchants", headers=ADM,
                    json={"name": name, "country": country, "agreement_signed": signed, "feed_config": feed})
    assert r.status_code == 200, r.text
    return {"X-API-Key": r.json()["api_key"]}, r.json()["merchant_id"]


# ---------------- normalization
@pytest.mark.parametrize("raw", ["0300-1234567", "+92 300 1234567", "923001234567", "0092 300 1234567"])
def test_pk_phone_variants_match(raw):
    assert normalize_phone(raw, "PK") == "+923001234567"


@pytest.mark.parametrize("raw", ["050 123 4567", "+971501234567", "971501234567", "00971 50 123 4567"])
def test_uae_phone_variants_match(raw):
    assert normalize_phone(raw, "AE") == "+971501234567"


def test_invalid_phone():
    assert normalize_phone("12345", "PK") is None


def test_email_normalization():
    assert normalize_email("Ali.Khan+shop@GMail.com") == "alikhan@gmail.com"


# ---------------- API flow
def test_full_flow_and_corroboration():
    k1, _ = new_merchant("Store A")
    k2, _ = new_merchant("Store B")
    k3, _ = new_merchant("Store C", country="AE")
    phone = "0321-7654321"

    # unknown customer
    r = client.post("/v1/check", headers=k1, json={"phone": phone})
    assert r.json()["band"] == "low" and r.json()["score"] == 0

    # merchant A reports 3 refusals -> capped at medium (single source)
    for i in range(3):
        r = client.post("/v1/events", headers=k1, json={
            "order_ref": f"A-{i}", "type": "refused_at_door", "occurred_at": iso(5), "phone": phone})
        assert r.status_code == 201 and r.json()["outcome"] == "created"
    r = client.post("/v1/check", headers=k2, json={"phone": "+923217654321"})
    body = r.json()
    assert body["score"] <= 59 and body["reporting_merchants"] == 1

    # merchant B corroborates -> high
    client.post("/v1/events", headers=k2, json={
        "order_ref": "B-1", "type": "fake_order", "occurred_at": iso(2), "phone": phone})
    body = client.post("/v1/check", headers=k3, json={"phone": phone, "country": "PK"}).json()
    assert body["band"] == "high"
    assert body["recommended_action"] == "require_prepayment_or_partial_advance"


def test_duplicate_is_ignored():
    k, _ = new_merchant("Dup Store")
    payload = {"order_ref": "D-1", "type": "refused_at_door", "occurred_at": iso(), "phone": "03001112223"}
    assert client.post("/v1/events", headers=k, json=payload).json()["outcome"] == "created"
    assert client.post("/v1/events", headers=k, json=payload).json()["outcome"] == "duplicate"


def test_unsigned_merchant_cannot_report():
    k, _ = new_merchant("No Agreement", signed=False)
    r = client.post("/v1/events", headers=k, json={
        "order_ref": "X", "type": "refused_at_door", "occurred_at": iso(), "phone": "03001112224"})
    assert r.status_code == 422 and "agreement" in r.text


def test_validation_errors():
    k, _ = new_merchant("Val Store")
    bad_type = {"order_ref": "V1", "type": "bad_intention", "occurred_at": iso(), "phone": "03001112225"}
    assert client.post("/v1/events", headers=k, json=bad_type).status_code == 422
    addr_only = {"order_ref": "V2", "type": "refused_at_door", "occurred_at": iso(),
                 "address": "House 12 Street 4 DHA Phase 5", "city": "Lahore"}
    assert client.post("/v1/events", headers=k, json=addr_only).status_code == 422
    future = {"order_ref": "V3", "type": "refused_at_door",
              "occurred_at": (NOW + timedelta(days=3)).isoformat(), "phone": "03001112225"}
    assert client.post("/v1/events", headers=k, json=future).status_code == 422


def test_bad_api_key():
    assert client.post("/v1/check", headers={"X-API-Key": "nope"}, json={"phone": "0300"}).status_code == 401


def test_paid_deliveries_reduce_score():
    k1, _ = new_merchant("P1")
    k2, _ = new_merchant("P2")
    phone = "03335556667"
    client.post("/v1/events", headers=k1, json={"order_ref": "1", "type": "refused_at_door",
                                                "occurred_at": iso(3), "phone": phone})
    client.post("/v1/events", headers=k2, json={"order_ref": "2", "type": "refused_at_door",
                                                "occurred_at": iso(3), "phone": phone})
    before = client.post("/v1/check", headers=k1, json={"phone": phone}).json()["score"]
    for i in range(4):
        client.post("/v1/events", headers=k2, json={"order_ref": f"ok{i}", "type": "delivered_paid",
                                                    "occurred_at": iso(1), "phone": phone})
    after = client.post("/v1/check", headers=k1, json={"phone": phone}).json()
    assert after["score"] < before and after["paid_deliveries"] == 4


def test_old_events_decay():
    k1, _ = new_merchant("Old1")
    k2, _ = new_merchant("Old2")
    fresh, stale = "03451230001", "03451230002"
    for k, ref in ((k1, "a"), (k2, "b")):
        client.post("/v1/events", headers=k, json={"order_ref": ref + fresh, "type": "fake_order",
                                                   "occurred_at": iso(1), "phone": fresh})
        client.post("/v1/events", headers=k, json={"order_ref": ref + stale, "type": "fake_order",
                                                   "occurred_at": iso(500), "phone": stale})
    s_fresh = client.post("/v1/check", headers=k1, json={"phone": fresh}).json()["score"]
    s_stale = client.post("/v1/check", headers=k1, json={"phone": stale}).json()["score"]
    assert s_stale < s_fresh / 2


def test_uae_customer_and_email_match():
    k1, _ = new_merchant("Dubai1", "AE")
    k2, _ = new_merchant("Dubai2", "AE")
    client.post("/v1/events", headers=k1, json={"order_ref": "u1", "type": "return_abuse",
                                                "occurred_at": iso(), "phone": "0551234567",
                                                "email": "Sara.M@gmail.com"})
    # second merchant only has the email, written differently
    client.post("/v1/events", headers=k2, json={"order_ref": "u2", "type": "chargeback",
                                                "occurred_at": iso(), "email": "saram+x@gmail.com",
                                                "country": "AE"})
    body = client.post("/v1/check", headers=k1, json={"email": "SARAM@gmail.com", "country": "AE"}).json()
    assert body["reporting_merchants"] == 2


def test_dispute_freezes_then_restores_or_removes():
    k1, _ = new_merchant("Disp1")
    k2, _ = new_merchant("Disp2")
    phone = "03009998887"
    for k, ref in ((k1, "d1"), (k2, "d2")):
        client.post("/v1/events", headers=k, json={"order_ref": ref, "type": "refused_at_door",
                                                   "occurred_at": iso(), "phone": phone})
    assert client.post("/v1/check", headers=k1, json={"phone": phone}).json()["score"] > 0

    r = client.post("/v1/disputes", json={"phone": phone, "country": "PK",
                                          "reason": "I was abroad, I never placed these orders."})
    did = r.json()["dispute_id"]
    assert client.post("/v1/check", headers=k1, json={"phone": phone}).json()["score"] == 0

    # rejected -> events come back
    client.post(f"/v1/admin/disputes/{did}/resolve", headers=ADM, json={"upheld": False})
    assert client.post("/v1/check", headers=k1, json={"phone": phone}).json()["score"] > 0

    # new dispute upheld -> removed permanently
    did2 = client.post("/v1/disputes", json={"phone": phone, "country": "PK",
                                             "reason": "Courier marked refused but never came."}).json()["dispute_id"]
    client.post(f"/v1/admin/disputes/{did2}/resolve", headers=ADM, json={"upheld": True, "note": "courier error"})
    assert client.post("/v1/check", headers=k1, json={"phone": phone}).json()["score"] == 0


def test_dispute_unknown_number():
    r = client.post("/v1/disputes", json={"phone": "03110000000", "country": "PK",
                                          "reason": "checking whether I am listed"})
    assert r.status_code == 422


def test_no_raw_pii_in_database():
    k, _ = new_merchant("PII")
    client.post("/v1/events", headers=k, json={"order_ref": "pii", "type": "refused_at_door",
                                               "occurred_at": iso(), "phone": "03127778889",
                                               "email": "secret.person@example.com",
                                               "address": "House 9 Street 2 Gulberg", "city": "Lahore"})
    dump = Path(f"{_tmp}/test.db").read_bytes()
    for needle in (b"3127778889", b"secret.person", b"Gulberg", b"gulberg"):
        assert needle not in dump


def test_batch():
    k, _ = new_merchant("Batch")
    r = client.post("/v1/events/batch", headers=k, json=[
        {"order_ref": "b1", "type": "refused_at_door", "occurred_at": iso(), "phone": "03001230011"},
        {"order_ref": "b2", "type": "nonsense", "occurred_at": iso(), "phone": "03001230012"},
        {"order_ref": "b1", "type": "refused_at_door", "occurred_at": iso(), "phone": "03001230011"},
    ])
    outcomes = [x["outcome"] for x in r.json()["results"]]
    assert outcomes == ["created", "rejected", "duplicate"]


# ---------------- agents
def test_csv_ingest_agent_and_cursorless_rerun(tmp_path):
    from codshield.agents.runner import run_ingest
    inbox = tmp_path / "inbox"
    inbox.mkdir()
    (inbox / "oct.csv").write_text(
        "order_ref,type,occurred_at,phone,email,address,city,amount,currency,evidence\n"
        f"C1,refused_at_door,{iso(2)},0301-4445556,,,Karachi,4500,PKR,TCS123\n"
        f"C2,delivered_paid,{iso(1)},0301-4445557,,,Karachi,2000,PKR,\n"
        f"C3,bad_type,{iso(1)},0301-4445558,,,,,,\n"
        f"C4,fake_address,{iso(1)},,,,,,,\n", encoding="utf-8")
    _, mid = new_merchant("CSV Store", feed={"type": "csv", "inbox": str(inbox)})
    with SessionLocal() as s:
        res = [r for r in run_ingest(s) if r["merchant_id"] == mid][0]
    assert res["created"] == 2 and res["rejected"] == 2
    assert (inbox / "processed" / "oct.csv").exists()
    with SessionLocal() as s:  # second pass: inbox empty
        res2 = [r for r in run_ingest(s) if r["merchant_id"] == mid][0]
    assert res2["created"] == 0


def test_json_pull_agent_with_cursor(monkeypatch):
    import httpx

    from codshield.agents import connectors
    from codshield.agents.runner import run_ingest

    calls = []

    def handler(request: httpx.Request):
        calls.append(str(request.url))
        assert request.headers["Authorization"] == "Bearer t0k"
        return httpx.Response(200, json={"events": [
            {"order_ref": "J1", "type": "unreachable", "occurred_at": iso(1), "phone": "0555123456", "country": "AE"}],
            "next_cursor": "2026-10-14T00:00:00Z"})

    real_client = httpx.Client
    monkeypatch.setattr(connectors.httpx, "Client",
                        lambda **kw: real_client(transport=httpx.MockTransport(handler), **kw))
    monkeypatch.setenv("JSON_TOKEN", "t0k")
    _, mid = new_merchant("JSON Store", "AE", feed={"type": "json", "url": "https://merchant.example/feed",
                                                    "token_env": "JSON_TOKEN"})
    with SessionLocal() as s:
        res = [r for r in run_ingest(s) if r["merchant_id"] == mid][0]
    assert res["created"] == 1
    with SessionLocal() as s:
        assert s.get(Merchant, mid).feed_config["cursor"] == "2026-10-14T00:00:00Z"
        run_ingest(s)
    assert "since=2026-10-14" in calls[-1]


def test_shopify_mapping():
    from codshield.agents.connectors import _shopify_type
    rto = {"rto"}
    assert _shopify_type({"tags": "VIP, RTO"}, rto) == "refused_at_door"
    assert _shopify_type({"cancel_reason": "fraud"}, rto) == "fake_order"
    assert _shopify_type({"payment_gateway_names": ["Cash on Delivery (COD)"], "financial_status": "paid",
                          "fulfillment_status": "fulfilled"}, rto) == "delivered_paid"
    assert _shopify_type({"financial_status": "paid"}, rto) is None


def test_maintenance_purges_and_downgrades():
    from codshield.agents.runner import run_maintenance
    from codshield.service import report_event
    with SessionLocal() as s:
        m = Merchant(name="Abuser", country="PK", api_key_hash="x" * 64, agreement_signed_at=NOW)
        s.add(m)
        s.commit()
        for i in range(60):
            ev, _ = report_event(s, m, order_ref=f"ab{i}", type="refused_at_door",
                                 occurred_at=NOW - timedelta(days=1), phone=f"0300{1000000 + i}")
            if i < 20:
                ev.status = "removed"
        old, _ = report_event(s, m, order_ref="old", type="fake_order",
                              occurred_at=NOW - timedelta(days=700), phone="03009990000")
        old.occurred_at = NOW - timedelta(days=800)  # simulate aged-out record
        s.commit()
        stats = run_maintenance(s)
        assert stats["purged_events"] >= 1
        assert m.id in stats["downgraded_merchants"]
        assert s.get(Merchant, m.id).trust_weight == 0.5
        s.expunge_all()
        assert s.get(Event, old.id) is None


def test_hosted_without_secrets_refuses_data(monkeypatch):
    monkeypatch.setenv("RENDER", "true")
    from codshield import api
    monkeypatch.setattr(api.settings, "ADMIN_KEY", "dev-admin-key")
    r = client.post("/v1/check", headers={"X-API-Key": "x"}, json={"phone": "03001234567"})
    assert r.status_code == 503 and "CODSHIELD_ADMIN_KEY" in r.text
    assert client.get("/health").status_code == 200
    assert client.get("/").status_code == 200
