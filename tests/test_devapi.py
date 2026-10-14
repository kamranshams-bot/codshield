"""Developer API platform: scoped keys, sandbox, usage metering, score-only tier, webhooks."""
import hashlib
import hmac
import json
import os

os.environ.setdefault("CODSHIELD_WEBHOOKS_ALLOW_PRIVATE", "1")

import httpx  # noqa: E402
import pytest  # noqa: E402

from tests.test_saas import (add_user, c, login, new_tenant, outcome,  # noqa: E402
                             platform_session, uniq)

from codshield import devapi  # noqa: E402


def make_key(H, scopes, mode="live", name="ERP"):
    r = c.post("/v1/api-keys", headers=H, json={"name": name, "mode": mode, "scopes": scopes})
    assert r.status_code == 201, r.text
    return {"X-API-Key": r.json()["api_key"]}, r.json()["key"]


def test_scoped_keys():
    _, H, _ = new_tenant(approval=False)
    chk, info = make_key(H, ["check"])
    assert info["prefix"].startswith("cs_live_") and info["scopes"] == ["check"]
    assert c.post("/v1/check", headers=chk, json={"phone": "03001234567"}).status_code == 200
    r = c.post("/v1/events", headers=chk, json=outcome(uniq("K"), "03001234567"))
    assert r.status_code == 403 and "report" in r.text
    assert c.get("/v1/reports", headers=chk).status_code == 403
    rep, _ = make_key(H, ["report", "read"])
    assert c.post("/v1/events", headers=rep, json=outcome(uniq("K"), "03001234567")).json()["outcome"] == "created"
    assert c.get("/v1/reports", headers=rep).status_code == 200
    # keys can't manage keys
    assert c.post("/v1/api-keys", headers=rep, json={"name": "x", "scopes": ["check"]}).status_code == 403


def test_revoked_key_stops_working():
    _, H, _ = new_tenant()
    k, info = make_key(H, ["check"])
    assert c.delete(f"/v1/api-keys/{info['id']}", headers=H).json()["revoked"] is True
    assert c.post("/v1/check", headers=k, json={"phone": "03001234567"}).status_code == 401
    names = [x["name"] for x in c.get("/v1/api-keys", headers=H).json()]
    assert "ERP" in names


def test_sandbox_mode():
    _, H, _ = new_tenant()
    t, info = make_key(H, ["check", "report"], mode="test")
    assert info["prefix"].startswith("cs_test_")
    r = c.post("/v1/check", headers=t, json={"phone": "+92 300 0000001"}).json()
    assert r["band"] == "high" and r["test_mode"] is True
    assert c.post("/v1/check", headers=t, json={"phone": "+971 50 000 0002", "country": "AE"}).json()["band"] == "medium"
    assert c.post("/v1/check", headers=t, json={"phone": "03009998887"}).json()["band"] == "low"
    r = c.post("/v1/events", headers=t, json=outcome(uniq("T"), "03001234567"))
    assert r.json()["outcome"] == "test_accepted"
    assert c.post("/v1/events", headers=t, json=outcome(uniq("T"), "123")).status_code == 422
    b = c.post("/v1/events/batch", headers=t, json=[outcome(uniq("T"), "03001234567"), outcome("x", "1")]).json()
    assert [x["outcome"] for x in b["results"]] == ["test_accepted", "rejected"]
    # nothing stored, no checks counted
    me = c.get("/v1/me", headers=H).json()["tenant"]
    assert me["checks_this_month"] == 0
    live = c.post("/v1/check", headers=H, json={"phone": "+923000000001"}).json()
    assert live["band"] == "low" and "test_mode" not in live


def test_usage_metering():
    _, H, _ = new_tenant()
    k, _ = make_key(H, ["check", "read"], name="Shopify")
    for _ in range(3):
        c.post("/v1/check", headers=k, json={"phone": "03001234567"})
    c.post("/v1/check", headers=k, json={"phone": "1"})        # error
    u = c.get("/v1/usage", headers=H).json()
    assert u["total_calls"] == 4 and u["error_calls"] == 1
    assert any("Shopify" in name for name, _ in u["by_key"])
    assert ["POST /v1/check", 4] in [list(x) for x in u["by_endpoint"]]
    assert sum(u["daily"]["calls"]) == 4
    r = c.post("/v1/check", headers=k, json={"phone": "03001234567"})
    assert r.headers["X-Request-ID"].startswith("req_")


def test_score_only_tier():
    P = platform_session()
    mid, H, _ = new_tenant(approval=False)
    _, H2, _ = new_tenant(approval=False)
    phone = "0311" + str(3000000 + int(uniq("")))
    c.post("/v1/events", headers=H2, json=outcome(uniq("S"), phone))
    assert c.patch(f"/v1/admin/merchants/{mid}", headers=P, json={"tier": "score_only"}).json()["tier"] == "score_only"
    r = c.post("/v1/check", headers=H, json={"phone": phone}).json()
    assert r["detail"] == "score_only_tier" and "reasons" not in r and r["band"] in ("low", "medium", "high")
    assert c.post("/v1/events", headers=H, json=outcome(uniq("S"), phone)).status_code == 403
    r = c.post("/v1/api-keys", headers=H, json={"name": "x", "scopes": ["report"]})
    assert r.status_code == 403
    me = c.get("/v1/me", headers=H).json()
    assert me["tenant"]["tier"] == "score_only" and "submit" not in me["perms"]


class Hook:
    def __init__(self, status=200):
        self.calls, self.status = [], status

    def __call__(self, request: httpx.Request):
        self.calls.append(request)
        return httpx.Response(self.status)


@pytest.fixture
def hook(monkeypatch):
    h = Hook()
    real = httpx.Client
    monkeypatch.setattr(devapi, "SYNC", True)
    monkeypatch.setattr(devapi, "_client_factory", lambda: real(transport=httpx.MockTransport(h), timeout=5))
    return h


def test_webhooks_signed_and_events(hook):
    _, H, _ = new_tenant()
    _, maker = add_user(H, ["submit"])
    _, checker = add_user(H, ["approve"])
    r = c.post("/v1/webhooks", headers=H, json={"url": "https://hooks.example.com/cod", "events": ["entry.approved", "dispute.opened"]})
    assert r.status_code == 201, r.text
    secret, ep = r.json()["signing_secret"], r.json()["endpoint"]
    assert c.post(f"/v1/webhooks/{ep['id']}/test", headers=H).json()["status"] == "delivered"
    phone = "0346" + str(4000000 + int(uniq("")))
    sid = c.post("/v1/events", headers=maker, json=outcome(uniq("W"), phone)).json()["submission_id"]
    c.post("/v1/submissions/approve", headers=checker, json={"ids": [sid]})
    req = hook.calls[-1]
    body = json.loads(req.content)
    assert req.headers["X-CODShield-Event"] == "entry.approved" and body["data"]["entries"][0]["submission_id"] == sid
    t, v1 = [x.split("=", 1)[1] for x in req.headers["X-CODShield-Signature"].split(",")]
    assert hmac.compare_digest(v1, hmac.new(secret.encode(), f"{t}.".encode() + req.content, hashlib.sha256).hexdigest())
    # a dispute about this phone notifies the store
    n = len(hook.calls)
    c.post("/v1/disputes", json={"phone": phone, "country": "PK", "reason": "I never ordered anything from this store."})
    assert len(hook.calls) == n + 1 and hook.calls[-1].headers["X-CODShield-Event"] == "dispute.opened"
    # not subscribed -> nothing sent
    n = len(hook.calls)
    sid2 = c.post("/v1/events", headers=maker, json=outcome(uniq("W"), phone)).json()["submission_id"]
    c.post("/v1/submissions/reject", headers=checker, json={"ids": [sid2], "reason": "dup"})
    assert len(hook.calls) == n
    hist = c.get("/v1/webhooks", headers=H).json()["endpoints"][0]["recent"]
    assert hist[0]["status"] == "delivered"


def test_webhook_failures_retry(monkeypatch):
    h = Hook(status=500)
    real = httpx.Client
    monkeypatch.setattr(devapi, "SYNC", True)
    monkeypatch.setattr(devapi, "_client_factory", lambda: real(transport=httpx.MockTransport(h), timeout=5))
    _, H, _ = new_tenant()
    ep = c.post("/v1/webhooks", headers=H, json={"url": "https://hooks.example.com/x", "events": ["quota.warning"]}).json()["endpoint"]
    r = c.post(f"/v1/webhooks/{ep['id']}/test", headers=H).json()
    assert r["status"] == "pending" and r["response_code"] == 500
    from codshield.db import SessionLocal
    from codshield.models import WebhookDelivery, utcnow
    from datetime import timedelta
    with SessionLocal() as s:
        d = s.query(WebhookDelivery).filter_by(endpoint_id=ep["id"]).first()
        d.last_attempt_at = utcnow() - timedelta(hours=1)
        s.commit()
        h.status = 200
        assert devapi.retry_due(s) >= 1
        s.expire_all()
        assert s.get(WebhookDelivery, d.id).status == "delivered"


def test_webhook_url_guard(monkeypatch):
    monkeypatch.delenv("CODSHIELD_WEBHOOKS_ALLOW_PRIVATE", raising=False)
    for bad in ("http://example.com/x", "https://127.0.0.1/x", "https://localhost/x", "https://10.0.0.5/hook", "https://169.254.169.254/latest"):
        with pytest.raises(devapi.PlatformError):
            devapi.validate_url(bad)


def test_quota_warning_event(hook, monkeypatch):
    from codshield import auth
    _, H, _ = new_tenant(plan="free")
    c.post("/v1/webhooks", headers=H, json={"url": "https://hooks.example.com/q", "events": ["quota.warning"]})
    monkeypatch.setitem(auth.PLANS["free"], "checks", 5)
    for i in range(4):
        c.post("/v1/check", headers=H, json={"phone": f"0300111000{i}"})
    evs = [r.headers["X-CODShield-Event"] for r in hook.calls]
    assert evs.count("quota.warning") == 1


def test_meta_documents_api():
    m = c.get("/v1/meta").json()["api"]
    assert set(m["scopes"]) == {"check", "report", "read"} and "+923000000001" in m["sandbox_numbers"]
    assert c.get("/developers").status_code == 200
    spec = c.get("/openapi.json").json()
    assert "/v1/api-keys" in spec["paths"] and "/v1/check" in spec["paths"]
