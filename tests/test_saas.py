"""Multi-tenant SaaS: sign-in, roles, countries, maker-checker, plans, disputes, audit."""
import os
import tempfile
from datetime import datetime, timedelta, timezone

if "CODSHIELD_DATABASE_URL" not in os.environ:
    os.environ["CODSHIELD_DATABASE_URL"] = f"sqlite:///{tempfile.mkdtemp()}/saas.db"
    os.environ["CODSHIELD_HASH_SECRET"] = "test-secret"
    os.environ["CODSHIELD_ADMIN_KEY"] = "adm"

from fastapi.testclient import TestClient  # noqa: E402
from tests import verified_dispute  # noqa: E402

from codshield.api import app  # noqa: E402
from codshield.config import settings  # noqa: E402
from codshield.db import init_db  # noqa: E402

init_db()
c = TestClient(app)
ADM = {"X-Admin-Key": settings.ADMIN_KEY}
NOW = datetime.now(timezone.utc).replace(tzinfo=None)
_n = iter(range(10_000))


def uniq(prefix):
    return f"{prefix}{next(_n)}"


def bearer(tok):
    return {"Authorization": f"Bearer {tok}"}


def login(email, pw):
    r = c.post("/v1/auth/login", json={"email": email, "password": pw})
    assert r.status_code == 200, r.text
    return bearer(r.json()["token"])


_owner = {}


def platform_session():
    if _owner.get("h") and c.get("/v1/me", headers=_owner["h"]).status_code == 200:
        return _owner["h"]
    meta = c.get("/v1/meta").json()
    email = "owner@codshield.test"
    if meta["setup_required"]:
        r = c.post("/v1/auth/setup", headers=ADM, json={"email": email, "name": "Owner", "password": "owner-pass-123"})
        assert r.status_code == 200, r.text
    _owner["h"] = login(email, "owner-pass-123")
    return _owner["h"]


def new_tenant(country="PK", plan="growth", approval=True):
    P = platform_session()
    admin_email = uniq("admin") + "@store.test"
    r = c.post("/v1/admin/merchants", headers=P, json={
        "name": uniq("Store "), "country": country, "agreement_signed": True, "plan": plan,
        "require_approval": approval, "admin_email": admin_email, "admin_name": "Store Admin"})
    assert r.status_code == 201, r.text
    body = r.json()
    tmp = body["admin_user"]["temporary_password"]
    H = login(admin_email, tmp)
    assert c.get("/v1/me", headers=H).json()["user"]["must_change_password"] is True
    assert c.post("/v1/auth/password", headers=H, json={"current_password": tmp, "new_password": "store-pass-123"}).status_code == 200
    return body["merchant_id"], H, body["api_key"]


def add_user(H, perms, countries=("PK", "AE"), **extra):
    email = uniq("u") + "@store.test"
    r = c.post("/v1/users", headers=H, json={"email": email, "name": email.split("@")[0], "perms": perms,
                                            "countries": list(countries), **extra})
    assert r.status_code == 201, r.text
    return r.json()["user"]["id"], login(email, r.json()["temporary_password"])


def outcome(ref, phone, typ="refused_at_door", country="PK"):
    return {"order_ref": ref, "type": typ, "occurred_at": (NOW - timedelta(days=1)).isoformat(),
            "phone": phone, "country": country}


# ------------------------------------------------------------------ sign-in
def test_setup_only_once_and_login_errors():
    platform_session()
    r = c.post("/v1/auth/setup", headers=ADM, json={"email": "x@y.test", "name": "X", "password": "another-pass-1"})
    assert r.status_code == 409
    assert c.post("/v1/auth/login", json={"email": "owner@codshield.test", "password": "wrong"}).status_code == 401
    assert c.get("/v1/me").status_code == 401


def test_logout_ends_session():
    P = login("owner@codshield.test", "owner-pass-123") if not c.get("/v1/meta").json()["setup_required"] else platform_session()
    assert c.get("/v1/me", headers=P).status_code == 200
    c.post("/v1/auth/logout", headers=P)
    assert c.get("/v1/me", headers=P).status_code == 401


def test_weak_password_rejected():
    _, H, _ = new_tenant()
    r = c.post("/v1/auth/password", headers=H, json={"current_password": "store-pass-123", "new_password": "short"})
    assert r.status_code == 422


# ------------------------------------------------------------------ roles
def test_permissions_enforced():
    _, H, _ = new_tenant()
    _, viewer = add_user(H, ["reports"])
    assert c.post("/v1/check", headers=viewer, json={"phone": "03001234567"}).status_code == 403
    assert c.get("/v1/reports", headers=viewer).status_code == 200
    assert c.get("/v1/users", headers=viewer).status_code == 403
    assert c.post("/v1/events", headers=viewer, json=outcome("v1", "03001234567")).status_code == 403
    # store users can't reach platform endpoints
    assert c.get("/v1/admin/merchants", headers=H).status_code == 403


def test_country_scope():
    _, H, _ = new_tenant()
    _, pk_only = add_user(H, ["check", "submit"], ["PK"])
    assert c.post("/v1/check", headers=pk_only, json={"phone": "0501234567", "country": "AE"}).status_code == 403
    assert c.post("/v1/check", headers=pk_only, json={"phone": "03001234567", "country": "PK"}).status_code == 200
    r = c.post("/v1/events", headers=pk_only, json=outcome("c1", "0501234567", country="AE"))
    assert r.status_code == 403
    me = c.get("/v1/me", headers=pk_only).json()
    assert me["countries"] == ["PK"]


def test_tenant_admin_cannot_escalate():
    _, H, _ = new_tenant()
    r = c.post("/v1/users", headers=H, json={"email": uniq("p") + "@x.test", "perms": ["check"], "is_platform_admin": True})
    assert r.status_code == 403
    me = c.get("/v1/me", headers=H).json()["user"]
    assert c.patch(f"/v1/users/{me['id']}", headers=H, json={"perms": ["check"]}).status_code == 422
    assert c.patch(f"/v1/users/{me['id']}", headers=H, json={"active": False}).status_code == 422


def test_tenants_are_isolated():
    _, H1, _ = new_tenant()
    _, H2, _ = new_tenant()
    uid, _ = add_user(H1, ["check"])
    assert c.patch(f"/v1/users/{uid}", headers=H2, json={"active": False}).status_code == 404
    assert all(u["id"] != uid for u in c.get("/v1/users", headers=H2).json())


# ------------------------------------------------------------------ maker-checker
def test_maker_checker_flow():
    _, H, _ = new_tenant()
    _, maker = add_user(H, ["submit", "upload"])
    _, checker = add_user(H, ["approve", "check"])
    phone = "0333" + str(1000000 + next(_n))
    r = c.post("/v1/events", headers=maker, json=outcome(uniq("M"), phone))
    assert r.status_code == 201 and r.json()["outcome"] == "pending" and r.json()["requires_approval"]
    sid = r.json()["submission_id"]
    # not counted until approved
    assert c.post("/v1/check", headers=checker, json={"phone": phone}).json()["negative_events"] == 0
    pend = c.get("/v1/submissions", headers=checker).json()
    item = next(x for x in pend if x["id"] == sid)
    assert item["contact_hint"].startswith("+92") and phone[-4:] in item["contact_hint"] and phone[4:7] not in item["contact_hint"][3:-4]
    # maker can't approve own entry even if given approve rights
    assert c.post("/v1/submissions/approve", headers=maker, json={"ids": [sid]}).status_code == 403
    assert c.post("/v1/submissions/approve", headers=checker, json={"ids": [sid]}).json()["results"][0]["ok"]
    assert c.post("/v1/check", headers=checker, json={"phone": phone}).json()["negative_events"] == 1
    # already decided
    assert c.post("/v1/submissions/approve", headers=checker, json={"ids": [sid]}).json()["results"][0]["ok"] is False


def test_four_eyes_same_person():
    _, H, _ = new_tenant()
    _, both = add_user(H, ["submit", "approve"])
    sid = c.post("/v1/events", headers=both, json=outcome(uniq("F"), "03001112299")).json()["submission_id"]
    res = c.post("/v1/submissions/approve", headers=both, json={"ids": [sid]}).json()["results"][0]
    assert res["ok"] is False and "another checker" in res["error"]


def test_reject_needs_reason_and_batch_upload():
    _, H, _ = new_tenant()
    _, maker = add_user(H, ["upload"])
    _, checker = add_user(H, ["approve"])
    r = c.post("/v1/events/batch", headers=maker, json=[outcome(uniq("B"), "03004440001"), outcome(uniq("B"), "03004440002"),
                                                       {**outcome("bad", "123")}]).json()
    assert r["batch_ref"].startswith("B-") and [x["outcome"] for x in r["results"]] == ["pending", "pending", "rejected"]
    ids = [x["submission_id"] for x in r["results"] if x["outcome"] == "pending"]
    assert c.post("/v1/submissions/reject", headers=checker, json={"ids": ids}).status_code == 422
    out = c.post("/v1/submissions/reject", headers=checker, json={"ids": ids, "reason": "wrong courier ref"}).json()
    assert all(x["outcome"] == "rejected" for x in out["results"])
    mine = c.get("/v1/submissions?status=rejected", headers=maker).json()
    assert {x["id"] for x in mine} >= set(ids) and mine[0]["reject_reason"] == "wrong courier ref"
    # upload-only maker can't use single entry
    assert c.post("/v1/events", headers=maker, json=outcome(uniq("S"), "03004440003")).status_code == 403


def test_no_approval_tenant_and_api_key_record_directly():
    _, H, key = new_tenant(approval=False)
    _, maker = add_user(H, ["submit"])
    assert c.post("/v1/events", headers=maker, json=outcome(uniq("D"), "03005550001")).json()["outcome"] == "created"
    _, H2, key2 = new_tenant(approval=True)
    r = c.post("/v1/events", headers={"X-API-Key": key2}, json=outcome(uniq("K"), "03005550002"))
    assert r.json()["outcome"] == "created"


def test_pending_entries_hold_no_raw_phone():
    from codshield.db import SessionLocal
    from codshield.models import Submission
    _, H, _ = new_tenant()
    _, maker = add_user(H, ["submit"])
    sid = c.post("/v1/events", headers=maker, json=outcome(uniq("P"), "0300-7778889")).json()["submission_id"]
    with SessionLocal() as s:
        sub = s.get(Submission, sid)
        assert "7778889" not in str(sub.payload) + str(sub.identities)


# ------------------------------------------------------------------ plans
def test_seat_limit_and_check_quota(monkeypatch):
    mid, H, _ = new_tenant(plan="free")       # 3 seats incl. admin
    add_user(H, ["check"]); add_user(H, ["check"])
    r = c.post("/v1/users", headers=H, json={"email": uniq("x") + "@s.test", "perms": ["check"]})
    assert r.status_code == 402 and "plan" in r.text
    from codshield import auth
    monkeypatch.setitem(auth.PLANS["free"], "checks", 2)
    assert c.post("/v1/check", headers=H, json={"phone": "03001230001"}).status_code == 200
    assert c.post("/v1/check", headers=H, json={"phone": "03001230002"}).status_code == 200
    assert c.post("/v1/check", headers=H, json={"phone": "03001230003"}).status_code == 402
    P = platform_session()
    assert c.patch(f"/v1/admin/merchants/{mid}", headers=P, json={"plan": "growth"}).json()["plan"] == "growth"
    assert c.post("/v1/check", headers=H, json={"phone": "03001230003"}).status_code == 200


def test_suspended_tenant_cannot_sign_in():
    mid, H, _ = new_tenant()
    P = platform_session()
    c.patch(f"/v1/admin/merchants/{mid}", headers=P, json={"active": False})
    assert c.get("/v1/me", headers=H).status_code == 401


# ------------------------------------------------------------------ disputes
def test_store_dispute_response_withdraw():
    _, H, key = new_tenant(approval=False)
    _, H2, key2 = new_tenant(approval=False)
    phone = "0345" + str(2000000 + next(_n))
    c.post("/v1/events", headers=H, json=outcome(uniq("W"), phone))
    c.post("/v1/events", headers=H2, json=outcome(uniq("W"), phone, "fake_order"))
    _, disp = add_user(H, ["disputes"])
    did = verified_dispute(c, phone, "I never ordered from these shops.").json()["dispute_id"]
    mine = c.get("/v1/disputes", headers=disp).json()
    d = next(x for x in mine if x["id"] == did)
    assert len(d["your_records"]) == 1
    assert c.post(f"/v1/disputes/{did}/respond", headers=disp, json={"action": "withdraw", "note": "courier error"}).status_code == 200
    P = platform_session()
    pd = next(x for x in c.get("/v1/admin/disputes", headers=P).json() if x["id"] == did)
    assert pd["store_responses"][0]["action"] == "withdraw"
    # reject dispute: only the other store's record comes back
    c.post(f"/v1/admin/disputes/{did}/resolve", headers=P, json={"upheld": False})
    r = c.post("/v1/check", headers=H2, json={"phone": phone}).json()
    assert r["negative_events"] == 1 and r["reporting_merchants"] == 1


# ------------------------------------------------------------------ audit & key rotation
def test_audit_and_api_key_rotation():
    _, H, key = new_tenant()
    add_user(H, ["check"])
    new = c.post("/v1/tenant/api-key", headers=H).json()["api_key"]
    assert c.post("/v1/check", headers={"X-API-Key": key}, json={"phone": "03001234567"}).status_code == 401
    assert c.post("/v1/check", headers={"X-API-Key": new}, json={"phone": "03001234567"}).status_code == 200
    actions = [a["action"] for a in c.get("/v1/audit", headers=H).json()]
    assert {"user.created", "tenant.api_key_rotated", "auth.login"} <= set(actions)


# ------------------------------------------------------------------ email: reset and invitations
def _link_token(to):
    import re
    from tests import last_message
    return re.search(r"#(?:reset|invite)=(pw_[\w-]+)", last_message("email", to)["text"]).group(1)


def test_forgot_password_flow():
    _, H, _ = new_tenant()
    email = uniq("fp") + "@store.test"
    r = c.post("/v1/users", headers=H, json={"email": email, "name": "Fay", "perms": ["check"], "countries": ["PK"]}).json()
    assert r["invite_sent"] is True
    temp = r["temporary_password"]
    a = c.post("/v1/auth/forgot", json={"email": email}).json()
    b = c.post("/v1/auth/forgot", json={"email": "nobody-" + email}).json()
    assert a == b and a["ok"] is True                      # no account enumeration
    tok = _link_token(email)
    assert c.post("/v1/auth/reset", json={"token": tok, "new_password": "short"}).status_code == 422
    done = c.post("/v1/auth/reset", json={"token": tok, "new_password": "brand-new-pass-1"})
    assert done.status_code == 200 and done.json()["token"].startswith("sess_")
    assert c.post("/v1/auth/reset", json={"token": tok, "new_password": "another-pass-22"}).status_code == 400
    assert c.post("/v1/auth/login", json={"email": email, "password": temp}).status_code == 401
    login(email, "brand-new-pass-1")


def test_invite_link_sets_password_and_clears_first_login_change():
    _, H, _ = new_tenant()
    email = uniq("inv") + "@store.test"
    c.post("/v1/users", headers=H, json={"email": email, "name": "Ivy", "perms": ["check"], "countries": ["PK"]})
    tok = _link_token(email)
    h = {"Authorization": "Bearer " + c.post("/v1/auth/reset", json={"token": tok, "new_password": "my-own-pass-12"}).json()["token"]}
    assert c.get("/v1/me", headers=h).json()["user"]["must_change_password"] is False


def test_dispute_emails_store_officers():
    from tests import last_message, verified_dispute
    _, H, _ = new_tenant(approval=False)
    off = uniq("off") + "@store.test"
    c.post("/v1/users", headers=H, json={"email": off, "name": "Officer", "perms": ["disputes"], "countries": ["PK", "AE"]})
    phone = "0345" + str(6000000 + int(uniq("")))
    c.post("/v1/events", headers=H, json=outcome(uniq("EM"), phone))
    verified_dispute(c, phone, "I never ordered anything at all.")
    assert "contested" in last_message("email", off)["subject"]
