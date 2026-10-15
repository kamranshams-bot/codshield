"""Shopify connector against a simulated Shopify Admin API."""
import base64
import hashlib
import hmac
import json

import httpx
import pytest

from tests.test_saas import c, new_tenant, outcome, uniq

from codshield import shopify

SECRET = "shpss_test_secret"


class FakeShopify:
    def __init__(self):
        self.calls, self.tags, self.notes, self.subscriptions = [], {}, {}, []

    def __call__(self, req: httpx.Request):
        self.calls.append(req)
        if req.url.path == "/admin/oauth/access_token":
            body = json.loads(req.content)
            if body["client_secret"] != SECRET:
                return httpx.Response(400, json={"error": "invalid_client"})
            return httpx.Response(200, json={"access_token": "shpat_fake", "scope": "read_orders,write_orders",
                                             "expires_in": 86399})
        assert req.headers["X-Shopify-Access-Token"] == "shpat_fake"
        q = json.loads(req.content)
        v = q["variables"]
        if "shop { name }" in q["query"]:
            return httpx.Response(200, json={"data": {"shop": {"name": "Demo Store"}}})
        if "webhookSubscriptionCreate" in q["query"]:
            self.subscriptions.append((v["topic"], v["sub"]))
            return httpx.Response(200, json={"data": {"webhookSubscriptionCreate": {"webhookSubscription": {"id": "1"}, "userErrors": []}}})
        if "tagsAdd" in q["query"]:
            self.tags.setdefault(v["id"], []).extend(v["tags"])
            return httpx.Response(200, json={"data": {"tagsAdd": {"userErrors": []}}})
        if "orderUpdate" in q["query"]:
            self.notes[v["input"]["id"]] = v["input"]["note"]
            return httpx.Response(200, json={"data": {"orderUpdate": {"userErrors": []}}})
        return httpx.Response(400, json={"errors": [{"message": "unexpected"}]})


@pytest.fixture
def fake(monkeypatch):
    f = FakeShopify()
    real = httpx.Client
    monkeypatch.setattr(shopify, "SYNC", True)
    monkeypatch.setattr(shopify, "_client_factory", lambda: real(transport=httpx.MockTransport(f), timeout=5))
    return f


def sign(raw: bytes, secret=SECRET) -> str:
    return base64.b64encode(hmac.new(secret.encode(), raw, hashlib.sha256).digest()).decode()


def hook(iid, topic, order, secret=SECRET, shop=None):
    raw = json.dumps(order).encode()
    return c.post(f"/shopify/webhooks/{iid}", content=raw, headers={
        "X-Shopify-Hmac-Sha256": sign(raw, secret), "X-Shopify-Topic": topic, "X-Shopify-Webhook-Id": uniq("wh"),
        "X-Shopify-Shop-Domain": shop or "demo-" + str(iid) + ".myshopify.com", "Content-Type": "application/json"})


def order(n, phone, gateway="Cash on Delivery (COD)", tags="", **extra):
    return {"id": n, "name": f"#{n}", "admin_graphql_api_id": f"gid://shopify/Order/{n}", "email": "",
            "payment_gateway_names": [gateway], "tags": tags, "note": "Leave at gate",
            "total_price": "4500.00", "currency": "PKR", "created_at": "2026-10-10T10:00:00Z",
            "updated_at": "2026-10-12T10:00:00Z",
            "shipping_address": {"phone": phone, "address1": "House 9, Street 4", "city": "Lahore", "country_code": "PK"},
            **extra}


def connect(H, shop):
    r = c.post("/v1/integrations/shopify", headers=H, json={"shop": shop, "client_id": "cid", "client_secret": SECRET})
    assert r.status_code == 201, r.text
    return r.json()


def test_connect_validates_and_subscribes(fake):
    _, H, _ = new_tenant(approval=False)
    bad = c.post("/v1/integrations/shopify", headers=H, json={"shop": "x", "client_id": "cid", "client_secret": "wrong"})
    assert bad.status_code == 422 and "refused" in bad.json()["error"]["message"]
    assert c.post("/v1/integrations/shopify", headers=H, json={"shop": "not a shop!", "client_secret": SECRET,
                                                                "client_id": "c"}).status_code == 422
    v = connect(H, "Demo-A")
    assert v["shop"] == "demo-a.myshopify.com" and v["stats"]["shop_name"] == "Demo Store"
    assert {t for t, _ in fake.subscriptions} == {"ORDERS_CREATE", "ORDERS_UPDATED"}
    assert fake.subscriptions[0][1]["uri"].endswith(f"/shopify/webhooks/{v['id']}")
    assert "client_secret" not in json.dumps(c.get("/v1/integrations", headers=H).json())


def test_cod_order_checked_tagged_and_outcomes_reported(fake):
    _, H, _ = new_tenant(approval=False)
    _, H2, _ = new_tenant(approval=False)
    phone = "0321" + str(7000000 + int(uniq("")))
    c.post("/v1/events", headers=H2, json=outcome(uniq("S"), phone))
    c.post("/v1/events", headers=H2, json=outcome(uniq("S"), phone, typ="fake_order"))
    shop = f"demo-{uniq('')}.myshopify.com"
    iid = connect(H, shop)["id"]

    assert hook(iid, "orders/create", order(1001, phone), shop=shop).status_code == 200
    tags = fake.tags["gid://shopify/Order/1001"]
    assert tags[0] in ("codshield-medium", "codshield-high") and tags[1].startswith("codshield-score-")
    assert fake.notes["gid://shopify/Order/1001"].startswith("Leave at gate\nCODShield:")

    hook(iid, "orders/create", order(1002, phone, gateway="Stripe"), shop=shop)      # prepaid: not checked
    assert "gid://shopify/Order/1002" not in fake.tags

    assert hook(iid, "orders/create", order(1003, phone), secret="forged", shop=shop).status_code == 401

    hook(iid, "orders/updated", order(1001, phone, tags="codshield-high, cod-refused"), shop=shop)
    hook(iid, "orders/updated", order(1001, phone, tags="codshield-high, cod-refused"), shop=shop)   # repeat: no double count
    st = c.get("/v1/integrations", headers=H).json()["integrations"][0]["stats"]
    assert st["checked"] == 1 and st["outcomes_created"] == 1 and st.get("outcomes_duplicate") == 1

    hook(iid, "orders/updated", order(1004, phone, financial_status="paid", fulfillment_status="fulfilled"), shop=shop)
    st = c.get("/v1/integrations", headers=H).json()["integrations"][0]["stats"]
    assert st["outcomes_created"] == 2                                                   # auto delivered_paid
    rep = c.get("/v1/reports", headers=H, params={"days": 30}).json()
    assert rep["by_type"].get("refused_at_door") == 1 and rep["by_type"].get("delivered_paid") == 1


def test_paused_integration_ignores_orders(fake):
    _, H, _ = new_tenant(approval=False)
    shop = f"demo-{uniq('')}.myshopify.com"
    iid = connect(H, shop)["id"]
    assert c.patch(f"/v1/integrations/{iid}", headers=H, json={"active": False}).json()["active"] is False
    hook(iid, "orders/create", order(2001, "03001234567"), shop=shop)
    assert "gid://shopify/Order/2001" not in fake.tags
    assert c.delete(f"/v1/integrations/{iid}", headers=H).json()["removed"] is True


def test_woocommerce_plugin_download():
    import io
    import zipfile
    r = c.get("/downloads/codshield-woocommerce.zip")
    assert r.status_code == 200 and r.headers["content-type"] == "application/zip"
    names = zipfile.ZipFile(io.BytesIO(r.content)).namelist()
    assert "codshield/codshield.php" in names and "codshield/readme.txt" in names
