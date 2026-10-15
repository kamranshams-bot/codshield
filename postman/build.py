"""Build the Postman collection + environments from the test data.

    python testdata/generate.py && python postman/build.py
"""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DATA = ROOT.parent / "testdata" / "out"
LIVE_URL = "https://codshield-sx1i.onrender.com"


def load(name):
    return json.loads((DATA / name).read_text())


# ----------------------------------------------------------------- helpers
def auth(kind):
    if kind == "none":
        return {"type": "noauth"}
    if kind == "session":
        return {"type": "bearer", "bearer": [{"key": "token", "value": "{{sessionToken}}", "type": "string"}]}
    if kind == "checker":
        return {"type": "bearer", "bearer": [{"key": "token", "value": "{{checkerToken}}", "type": "string"}]}
    var, header = {"key": ("apiKey", "X-API-Key"), "key2": ("apiKey2", "X-API-Key"), "test": ("testApiKey", "X-API-Key"),
                   "admin": ("adminKey", "X-Admin-Key")}[kind]
    return {"type": "apikey", "apikey": [{"key": "key", "value": header, "type": "string"},
                                         {"key": "value", "value": "{{" + var + "}}", "type": "string"},
                                         {"key": "in", "value": "header", "type": "string"}]}


def tests(*lines, status=None):
    code = []
    if status:
        code.append(f'pm.test("status {status}", () => pm.response.to.have.status({status}));')
    code += lines
    return [{"listen": "test", "script": {"type": "text/javascript", "exec": code}}] if code else []


def req(name, method, path, *, body=None, query=None, desc="", status=200, saves=(), extra_tests=(), auth_kind=None,
        raw_body=None):
    segs = [s for s in path.strip("/").split("/")]
    url = {"raw": "{{baseUrl}}/" + path.strip("/") + ("?" + "&".join(f"{k}={v}" for k, v in query.items()) if query else ""),
           "host": ["{{baseUrl}}"], "path": segs}
    if query:
        url["query"] = [{"key": k, "value": str(v)} for k, v in query.items()]
    r = {"method": method, "header": [], "url": url, "description": desc}
    if body is not None or raw_body is not None:
        r["header"].append({"key": "Content-Type", "value": "application/json"})
        r["body"] = {"mode": "raw", "raw": raw_body if raw_body is not None else json.dumps(body, indent=2),
                     "options": {"raw": {"language": "json"}}}
    if auth_kind:
        r["auth"] = auth(auth_kind)
    lines = [f'pm.environment.set("{var}", {expr});' for var, expr in saves] + list(extra_tests)
    return {"name": name, "event": tests(*lines, status=status), "request": r}


def folder(name, desc, items, auth_kind=None):
    f = {"name": name, "description": desc, "item": items}
    if auth_kind:
        f["auth"] = auth(auth_kind)
    return f


# ----------------------------------------------------------------- sample bodies
outcome_one = {"order_ref": "TEST-PK-900001", "type": "refused_at_door", "occurred_at": "2026-10-12T15:30:00Z",
               "phone": "03001234567", "city": "Lahore", "country": "PK", "amount": 4500, "currency": "PKR",
               "evidence": "TCS CN 77812345"}
SANDBOX = [("+923000000001", "PK", "high"), ("+923000000002", "PK", "medium"), ("+923000000003", "PK", "low"),
           ("+971500000001", "AE", "high"), ("+971500000002", "AE", "medium"), ("+971500000003", "AE", "low")]

SCHEMA_LABELS = ["country IN", "country 'pakistan'", "currency PKRS", "order_ref too long", "evidence too long",
                 "amount not a number", "occurred_at 'yesterday'", "type missing", "order_ref missing"]
results_ok = 'pm.test("every row has an outcome", () => pm.response.json().results.forEach(r => pm.expect(r.outcome).to.be.a("string")));'
count_outcomes = ('const c = {}; pm.response.json().results.forEach(r => c[r.outcome] = (c[r.outcome] || 0) + 1); '
                  'console.log("outcomes", JSON.stringify(c)); pm.test("outcomes: " + JSON.stringify(c), () => true);')
count_bands = ('const c = {}; pm.response.json().results.forEach(r => c[r.band || "error"] = (c[r.band || "error"] || 0) + 1); '
               'pm.test("bands: " + JSON.stringify(c), () => true);')

# ----------------------------------------------------------------- folders (in run order)
def save_admin_user(prefix):
    return [(f"{prefix}Email", "pm.response.json().admin_user.email"),
            (f"{prefix}Password", "pm.response.json().admin_user.temporary_password")]


setup = folder("01. Start here: health and stores", "Wakes the server and creates two test stores with the X-Admin-Key. "
               "Saves the stores' keys to {{apiKey}} / {{apiKey2}} and the first store admin's login to {{userEmail}} / {{userPassword}}. "
               "Skip the two 'Add' requests if you already have a store and keys.", [
    req("Health", "GET", "/health", auth_kind="none",
        desc="The free server sleeps after 15 minutes; the first call can take ~50 seconds."),
    req("Meta (outcome types, scopes, events, sandbox numbers)", "GET", "/v1/meta", auth_kind="none"),
    req("First-time setup (first platform admin; once only)", "POST", "/v1/auth/setup",
        body={"email": "{{adminEmail}}", "name": "Platform Admin", "password": "{{adminPassword}}"}, status=None,
        desc="Only works on an empty system; afterwards it answers 409, which is fine."),
    req("Add store 1 (PK, with admin user)", "POST", "/v1/admin/merchants",
        body={"name": "Test Store PK {{$timestamp}}", "country": "PK", "agreement_signed": True, "plan": "growth",
              "require_approval": False, "tier": "contributor", "admin_email": "owner.{{$timestamp}}@example.com",
              "admin_name": "Store Owner"},
        saves=[("merchantId", "pm.response.json().merchant_id"), ("apiKey", "pm.response.json().api_key")]
        + save_admin_user("user")),
    req("Add store 2 (AE)", "POST", "/v1/admin/merchants",
        body={"name": "Test Store AE {{$timestamp}}", "country": "AE", "agreement_signed": True, "plan": "growth",
              "require_approval": False},
        saves=[("merchantId2", "pm.response.json().merchant_id"), ("apiKey2", "pm.response.json().api_key")]),
], "admin")

signin = folder("02. Sign in", "Logs in as {{userEmail}} and saves {{sessionToken}} (valid 12 hours).", [
    req("Log in", "POST", "/v1/auth/login", body={"email": "{{userEmail}}", "password": "{{userPassword}}"},
        auth_kind="none", saves=[("sessionToken", "pm.response.json().token")]),
    req("Set a permanent password", "POST", "/v1/auth/password",
        body={"current_password": "{{userPassword}}", "new_password": "{{newPassword}}"},
        extra_tests=['pm.environment.set("userPassword", pm.environment.get("newPassword"));'],
        desc="New users get a temporary password. newPassword needs 10+ characters."),
    req("Who am I", "GET", "/v1/me"),
], "session")

developer = folder("03. API keys and webhooks (store admin)", "Session token of a store user with the users permission.", [
    req("Create a live key (check + report + read)", "POST", "/v1/api-keys", status=201,
        body={"name": "Postman live", "mode": "live", "scopes": ["check", "report", "read"]},
        saves=[("apiKey", "pm.response.json().api_key")]),
    req("Create a test key (sandbox)", "POST", "/v1/api-keys", status=201,
        body={"name": "Postman sandbox", "mode": "test", "scopes": ["check", "report", "read"]},
        saves=[("testApiKey", "pm.response.json().api_key")]),
    req("Create a throwaway check-only key", "POST", "/v1/api-keys", status=201,
        body={"name": "Throwaway", "mode": "live", "scopes": ["check"]}, saves=[("keyId", "pm.response.json().key.id")]),
    req("Revoke the throwaway key", "DELETE", "/v1/api-keys/{{keyId}}"),
    req("List API keys", "GET", "/v1/api-keys"),
    req("Add a webhook", "POST", "/v1/webhooks", status=201,
        body={"url": "{{webhookUrl}}", "events": ["entry.approved", "entry.rejected", "dispute.opened",
                                                  "dispute.resolved", "quota.warning"]},
        saves=[("webhookId", "pm.response.json().endpoint.id"), ("webhookSecret", "pm.response.json().signing_secret")],
        desc="Put a https://webhook.site URL in webhookUrl to watch deliveries arrive. The signing secret is shown once."),
    req("Send a test ping", "POST", "/v1/webhooks/{{webhookId}}/test"),
    req("List webhooks (with recent deliveries)", "GET", "/v1/webhooks"),
    req("Pause / resume a webhook", "PATCH", "/v1/webhooks/{{webhookId}}", body={"active": True}),
], "session")

sandbox = folder("04. Sandbox (test key)", "Uses {{testApiKey}} (cs_test_…): fixed answers, nothing stored, no quota used.", [
    *[req(f"Check {p} → {band}", "POST", "/v1/check", body={"phone": p, "country": c},
          extra_tests=[f'pm.test("band is {band}", () => pm.expect(pm.response.json().band).to.eql("{band}"));',
                       'pm.test("test_mode", () => pm.expect(pm.response.json().test_mode).to.eql(true));'])
      for p, c, band in SANDBOX],
    req("Report one outcome (validated, not stored)", "POST", "/v1/events", body=outcome_one, status=201,
        extra_tests=['pm.test("test_accepted", () => pm.expect(pm.response.json().outcome).to.eql("test_accepted"));']),
    req("Report batch 1 (1,000 validated, not stored)", "POST", "/v1/events/batch",
        raw_body=json.dumps(load("outcomes_batch1.json")), extra_tests=[count_outcomes]),
], "test")

batches = [req(f"Report batch {i} (1,000 test outcomes, store {1 if i < 3 else 2})", "POST", "/v1/events/batch",
               raw_body=json.dumps(load(f"outcomes_batch{i}.json")), extra_tests=[results_ok, count_outcomes],
               auth_kind=None if i < 3 else "key2",
               desc="Synthetic TEST- records. Batches 3-5 go through store 2 ({{apiKey2}}) so customers are reported "
                    "by two stores and can reach the high band; one store alone is capped at medium.")
           for i in range(1, 6)]
outcomes = folder("05. Report outcomes (5,000 records)", "Uses {{apiKey}} (report scope); batches 3-5 use {{apiKey2}}. "
                  "API keys record directly, without approval.", [
    req("Report one outcome", "POST", "/v1/events", body=outcome_one, status=201),
    *batches,
])

checks = folder("06. Check orders", "Uses {{apiKey}} (check scope). Live checks count toward the monthly quota.", [
    req("Check one customer (phone)", "POST", "/v1/check", body={"phone": "{{disputePhone}}", "country": "PK"},
        extra_tests=['pm.test("has band", () => pm.expect(["low","medium","high"]).to.include(pm.response.json().band));']),
    req("Check one customer (phone + email + address)", "POST", "/v1/check",
        body={"phone": "0501234567", "email": "ali.khan@gmail.com", "address": "Flat 1204, Building 7, Al Nahda 2",
              "city": "Dubai", "country": "AE"}),
    req("Check batch (500 test customers)", "POST", "/v1/check/batch",
        raw_body=json.dumps(load("checks_500.json")), extra_tests=[count_bands]),
])

validation = folder("07. Validation tests (expected failures)", "Uses {{apiKey}}.", [
    req("Batch of 14 bad rows (each rejected)", "POST", "/v1/events/batch", raw_body=json.dumps(load("invalid_rows.json")),
        extra_tests=['pm.test("all rejected", () => pm.response.json().results.forEach(r => pm.expect(r.outcome).to.eql("rejected")));']),
    *[req(f"422: {label}", "POST", "/v1/events", body=b, status=422)
      for label, b in zip(SCHEMA_LABELS, load("invalid_schema.json"))],
    req("No key → 401", "POST", "/v1/check", body={"phone": "03001234567"}, status=401, auth_kind="none"),
])

team = folder("08. Team (store admin)", "Session token of a store user with the users permission.", [
    req("Add a checker (PK + AE)", "POST", "/v1/users", status=201,
        body={"email": "checker.{{$timestamp}}@example.com", "name": "Test Checker",
              "perms": ["check", "approve", "reports", "disputes"], "countries": ["PK", "AE"]},
        saves=[("checkerEmail", "pm.response.json().user.email"),
               ("checkerPassword", "pm.response.json().temporary_password")]),
    req("Add a maker (PK only)", "POST", "/v1/users", status=201,
        body={"email": "maker.{{$timestamp}}@example.com", "name": "Test Maker", "perms": ["check", "submit", "upload"],
              "countries": ["PK"]}, saves=[("userId", "pm.response.json().user.id")]),
    req("List users", "GET", "/v1/users"),
    req("Change a user's permissions", "PATCH", "/v1/users/{{userId}}", body={"perms": ["check", "submit"], "countries": ["PK", "AE"]}),
    req("Reset a user's password", "PATCH", "/v1/users/{{userId}}", body={"reset_password": True}),
    req("Deactivate a user", "PATCH", "/v1/users/{{userId}}", body={"active": False}),
], "session")

entries = folder("09. Entries and approvals (maker-checker)", "The store owner enters an outcome as maker; the checker approves it "
                 "(nobody can approve their own entry).", [
    req("Turn on approval for the store", "PATCH", "/v1/tenant", body={"require_approval": True}),
    req("Maker enters an outcome (waits for a checker)", "POST", "/v1/events", status=201,
        body=outcome_one | {"order_ref": "TEST-PK-{{$timestamp}}"},
        saves=[("submissionId", "pm.response.json().submission_id")],
        extra_tests=['pm.test("pending", () => pm.expect(pm.response.json().outcome).to.eql("pending"));']),
    req("Maker enters a second outcome", "POST", "/v1/events", status=201,
        body=outcome_one | {"order_ref": "TEST-PK-{{$timestamp}}-2", "type": "unreachable"},
        saves=[("submissionId2", "pm.response.json().submission_id")]),
    req("Checker logs in", "POST", "/v1/auth/login", body={"email": "{{checkerEmail}}", "password": "{{checkerPassword}}"},
        auth_kind="none", saves=[("checkerToken", "pm.response.json().token")]),
    req("Checker lists pending entries", "GET", "/v1/submissions", query={"status": "pending"}, auth_kind="checker"),
    req("Checker approves one", "POST", "/v1/submissions/approve", raw_body='{\n  "ids": [{{submissionId}}]\n}',
        auth_kind="checker",
        extra_tests=['pm.test("approved", () => pm.expect(pm.response.json().results[0].ok).to.eql(true));']),
    req("Checker rejects one (reason required)", "POST", "/v1/submissions/reject", auth_kind="checker",
        raw_body='{\n  "ids": [{{submissionId2}}],\n  "reason": "Wrong order number"\n}'),
    req("Maker sees their entries", "GET", "/v1/submissions", query={"status": "all"}),
    req("Turn approval off again", "PATCH", "/v1/tenant", body={"require_approval": False}),
], "session")

disputes = folder("10. Disputes", "A customer contests their records; the store answers; CODShield decides.", [
    req("Customer opens a dispute (public)", "POST", "/v1/disputes", auth_kind="none",
        body={"phone": "{{disputePhone}}", "country": "PK", "reason": "I never placed these orders. Please remove them.",
              "contact": "test@example.com"},
        saves=[("disputeId", "pm.response.json().dispute_id")],
        desc="disputePhone must have records (it defaults to the first customer in batch 1); otherwise 422."),
    req("Store lists open disputes on its records", "GET", "/v1/disputes"),
    req("Store responds (confirm or withdraw)", "POST", "/v1/disputes/{{disputeId}}/respond",
        body={"action": "confirm", "note": "Courier proof on file."},
        desc="withdraw removes your records now; confirm stands by them for CODShield's decision."),
    req("Platform lists open disputes", "GET", "/v1/admin/disputes", query={"status": "open"}, auth_kind="admin"),
    req("Platform decides (upheld removes the records)", "POST", "/v1/admin/disputes/{{disputeId}}/resolve",
        body={"upheld": False, "note": "Store confirmed with courier proof."}, auth_kind="admin"),
], "session")

reports = folder("11. Reports, usage and audit", "", [
    req("Store report, last 30 days", "GET", "/v1/reports", query={"days": 30}),
    req("Store report, last 365 days", "GET", "/v1/reports", query={"days": 365}),
    req("API usage, last 30 days", "GET", "/v1/usage", query={"days": 30}),
    req("Store activity log", "GET", "/v1/audit", query={"limit": 100}, auth_kind="session"),
])

platform = folder("12. Platform admin", "Uses the X-Admin-Key ({{adminKey}}).", [
    req("Network stats", "GET", "/v1/admin/stats"),
    req("List stores", "GET", "/v1/admin/merchants"),
    req("Network report, last 30 days", "GET", "/v1/admin/reports", query={"days": 30}),
    req("Add stores in bulk", "POST", "/v1/admin/merchants/batch",
        body=[{"name": "Bulk Store A {{$timestamp}}", "country": "PK", "agreement_signed": True},
              {"name": "Bulk Store B {{$timestamp}}", "country": "AE", "agreement_signed": True}]),
    req("Store 2: make score-only", "PATCH", "/v1/admin/merchants/{{merchantId2}}", body={"tier": "score_only"}),
    req("Store 2: score-only check (no reasons)", "POST", "/v1/check", body={"phone": "{{disputePhone}}", "country": "PK"},
        auth_kind="key2",
        extra_tests=['pm.test("score only", () => pm.expect(pm.response.json().detail).to.eql("score_only_tier"));']),
    req("Store 2: back to contributor, plan enterprise", "PATCH", "/v1/admin/merchants/{{merchantId2}}",
        body={"tier": "contributor", "plan": "enterprise"}),
    req("Store 2: suspend", "PATCH", "/v1/admin/merchants/{{merchantId2}}", body={"active": False}),
    req("Store 2: reactivate", "PATCH", "/v1/admin/merchants/{{merchantId2}}", body={"active": True}),
    req("Platform users", "GET", "/v1/users"),
    req("Add a platform admin", "POST", "/v1/users", status=201,
        body={"email": "ops.{{$timestamp}}@example.com", "name": "Ops Admin", "is_platform_admin": True, "perms": [],
              "countries": ["PK", "AE"]}),
    req("Network activity log", "GET", "/v1/audit", query={"limit": 200}),
], "admin")

runner_body = ('{\n  "order_ref": "{{order_ref}}",\n  "type": "{{type}}",\n  "occurred_at": "{{occurred_at}}",\n'
               '  "phone": "{{phone}}",\n  "email": "{{email}}",\n  "address": "{{address}}",\n  "city": "{{city}}",\n'
               '  "country": "{{country}}",\n  "amount": {{amount}},\n  "currency": "{{currency}}",\n  "evidence": "{{evidence}}"\n}')
runner = folder("13. Data-file runner (run on its own)", "Run only this folder in the Collection Runner with "
                "testdata/out/outcomes_all.csv (or a part file) as the data file: one call per row. Slower than the "
                "batches (Free plan: 60 calls a minute; Growth: 600).", [
    req("Report one outcome from the data file", "POST", "/v1/events", raw_body=runner_body, status=201,
        extra_tests=['pm.test("recorded", () => pm.expect(["created","duplicate","pending"]).to.include(pm.response.json().outcome));']),
])

collection = {
    "info": {"name": "CODShield API v1",
             "description": "Every CODShield endpoint, with 5,000 synthetic TEST- outcomes and 500 checks.\n\n"
                            "Quick start\n1. Import the collection and the Live (or Local) environment; select it.\n"
                            "2. In the environment fill adminKey, adminEmail/adminPassword (first-time setup only) "
                            "and newPassword (10+ characters).\n"
                            "3. Run the whole collection in the Collection Runner (folders 01-12, skip 13), or "
                            "send requests one by one. Each request saves the IDs and keys the next ones need.\n\n"
                            "Credentials: apiKey / apiKey2 / testApiKey → X-API-Key; sessionToken / checkerToken → "
                            "Bearer; adminKey → X-Admin-Key.\n\n"
                            "Remove the test data afterwards: python -m codshield.testdata purge",
             "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"},
    "auth": auth("key"),
    "event": [{"listen": "test", "script": {"type": "text/javascript", "exec": [
        'if (pm.response.code >= 400) console.log(pm.info.requestName, pm.response.code, pm.response.text());']}}],
    "item": [setup, signin, developer, sandbox, outcomes, checks, validation, team, entries, disputes, reports, platform, runner],
}


def env(name, base):
    vals = [("baseUrl", base, "default"), ("apiKey", "", "secret"), ("apiKey2", "", "secret"), ("testApiKey", "", "secret"),
            ("adminKey", "", "secret"), ("sessionToken", "", "secret"), ("userEmail", "", "default"),
            ("userPassword", "", "secret"), ("newPassword", "", "secret"), ("adminEmail", "", "default"),
            ("adminPassword", "", "secret"), ("webhookUrl", "https://webhook.site/your-id", "default"),
            ("webhookSecret", "", "secret"), ("disputePhone", "", "default"), ("merchantId", "", "default"),
            ("userId", "", "default"), ("keyId", "", "default"), ("webhookId", "", "default"),
            ("disputeId", "", "default"), ("submissionId", "", "default"), ("submissionId2", "", "default"),
            ("merchantId2", "", "default"), ("checkerEmail", "", "default"), ("checkerPassword", "", "secret"),
            ("checkerToken", "", "secret")]
    return {"name": name, "values": [{"key": k, "value": v, "type": t, "enabled": True} for k, v, t in vals],
            "_postman_variable_scope": "environment"}


def main():
    # the first customer with history is a handy dispute target
    first = load("outcomes_batch1.json")[0]["phone"]
    live, local = env("CODShield Live", LIVE_URL), env("CODShield Local", "http://127.0.0.1:8000")
    for e in (live, local):
        next(v for v in e["values"] if v["key"] == "disputePhone")["value"] = first
    (ROOT / "CODShield.postman_collection.json").write_text(json.dumps(collection, indent=1))
    (ROOT / "CODShield-Live.postman_environment.json").write_text(json.dumps(live, indent=1))
    (ROOT / "CODShield-Local.postman_environment.json").write_text(json.dumps(local, indent=1))
    n = sum(len(f["item"]) for f in collection["item"])
    print(f"{n} requests in {len(collection['item'])} folders → {ROOT}")


if __name__ == "__main__":
    main()
