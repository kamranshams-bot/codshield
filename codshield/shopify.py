"""Shopify connector: checks new cash-on-delivery orders and reports outcomes from order tags.

How a store connects (no app review needed):
  1. In Shopify's Dev Dashboard, create an app for the store with the scopes read_orders and write_orders,
     and install it on the store.
  2. In CODShield (Developers > Shopify), enter the shop address, the app's client ID and client secret.
CODShield gets a 24-hour access token with the client credentials grant (renewed automatically) and
subscribes to the orders/create and orders/updated webhooks, which Shopify signs with the client secret.

  orders/create  -> COD order: score the customer, tag the order "codshield-high" / "-medium" / "-low"
                    plus "codshield-score-NN", and add a short note for staff.
  orders/updated -> staff tag the order with an outcome (cod-refused, cod-delivered, ...): report it.
                    Optionally, a paid and fulfilled COD order counts as delivered_paid automatically.

Stores with an older "legacy custom app" can paste its Admin API access token (shpat_...) instead of
a client ID; the API secret key is still needed to verify webhooks.
"""
import base64
import hashlib
import hmac
import logging
import re
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import notify, service
from .config import settings
from .models import Integration, Merchant, utcnow

log = logging.getLogger("codshield")
API_VERSION = "2026-07"
SHOP_RE = re.compile(r"^[a-z0-9][a-z0-9-]*\.myshopify\.com$")
TOPICS = {"ORDERS_CREATE": "orders/create", "ORDERS_UPDATED": "orders/updated"}

OUTCOME_TAGS = {
    "cod-refused": "refused_at_door",
    "cod-unreachable": "unreachable",
    "cod-fake-order": "fake_order",
    "cod-fake-address": "fake_address",
    "cod-return-abuse": "return_abuse",
    "cod-chargeback": "chargeback",
    "cod-delivered": "delivered_paid",
}
DEFAULT_SETTINGS = {"check_all_orders": False, "add_note": True, "auto_delivered": True}
ACTION_TEXT = {"low": "ship normally", "medium": "confirm by call or OTP before shipping",
               "high": "ask for prepayment or a part advance"}

SYNC = False                                  # tests: process webhooks inline
_client_factory = lambda: httpx.Client(timeout=15)   # noqa: E731  (tests swap this)
_pool = ThreadPoolExecutor(max_workers=2)
_seen_webhooks: deque = deque(maxlen=2000)    # Shopify may deliver the same webhook more than once


class ShopifyError(Exception):
    pass


def normalize_shop(shop: str) -> str:
    shop = (shop or "").strip().lower().removeprefix("https://").removeprefix("http://").split("/")[0]
    if shop and "." not in shop:
        shop += ".myshopify.com"
    if not SHOP_RE.match(shop):
        raise ShopifyError("Enter the store's myshopify.com address, e.g. mystore.myshopify.com")
    return shop


# ------------------------------------------------------------------ Shopify API
def _token(s: Session, integ: Integration) -> str:
    if not integ.client_id:                                   # legacy custom app: fixed token
        return notify.decrypt(integ.token_enc)
    if integ.token_enc and integ.token_expires_at and integ.token_expires_at > utcnow() + timedelta(minutes=5):
        return notify.decrypt(integ.token_enc)
    with _client_factory() as c:
        r = c.post(f"https://{integ.shop}/admin/oauth/access_token",
                   json={"client_id": integ.client_id, "client_secret": notify.decrypt(integ.secret_enc),
                         "grant_type": "client_credentials"})
    if r.status_code != 200:
        raise ShopifyError(f"Shopify refused the client ID and secret (HTTP {r.status_code}). "
                           "Check them, and that the app is installed on this store.")
    body = r.json()
    integ.token_enc = notify.encrypt(body["access_token"])
    integ.token_expires_at = utcnow() + timedelta(seconds=int(body.get("expires_in", 86399)))
    s.commit()
    return body["access_token"]


def graphql(s: Session, integ: Integration, query: str, variables: dict | None = None) -> dict:
    token = _token(s, integ)
    with _client_factory() as c:
        r = c.post(f"https://{integ.shop}/admin/api/{API_VERSION}/graphql.json",
                   headers={"X-Shopify-Access-Token": token}, json={"query": query, "variables": variables or {}})
    if r.status_code == 401:
        integ.token_expires_at = None
        s.commit()
        raise ShopifyError("Shopify rejected the access token. Reconnect the store.")
    if r.status_code != 200:
        raise ShopifyError(f"Shopify API error (HTTP {r.status_code})")
    data = r.json()
    if data.get("errors"):
        raise ShopifyError("Shopify API error: " + "; ".join(e.get("message", "") for e in data["errors"])[:300])
    return data["data"]


def _subscribe(s: Session, integ: Integration) -> list[str]:
    url = f"{settings.PUBLIC_URL}/shopify/webhooks/{integ.id}"
    done = []
    for topic in TOPICS:
        last_err = None
        for field in ("uri", "callbackUrl"):                  # uri replaced callbackUrl; older shops may need it
            try:
                d = graphql(s, integ, """mutation($topic: WebhookSubscriptionTopic!, $sub: WebhookSubscriptionInput!) {
                    webhookSubscriptionCreate(topic: $topic, webhookSubscription: $sub) {
                      webhookSubscription { id } userErrors { field message } } }""",
                            {"topic": topic, "sub": {field: url, "format": "JSON"}})
            except ShopifyError as e:
                last_err = str(e)
                continue
            errs = d["webhookSubscriptionCreate"]["userErrors"]
            if not errs or any("already" in (e.get("message") or "").lower() for e in errs):
                done.append(topic)
                last_err = None
                break
            last_err = "; ".join(e["message"] for e in errs)
        if last_err:
            raise ShopifyError(f"Couldn't subscribe to {TOPICS[topic]}: {last_err}")
    return done


def connect(s: Session, merchant: Merchant, *, shop: str, client_secret: str, client_id: str | None = None,
            access_token: str | None = None, options: dict | None = None) -> Integration:
    shop = normalize_shop(shop)
    if not client_secret:
        raise ShopifyError("Enter the app's client secret (it also verifies Shopify's webhooks).")
    if not client_id and not access_token:
        raise ShopifyError("Enter the app's client ID (or, for a legacy custom app, its Admin API access token).")
    integ = s.scalar(select(Integration).where(Integration.merchant_id == merchant.id, Integration.kind == "shopify",
                                               Integration.shop == shop))
    if integ is None:
        other = s.scalar(select(Integration).where(Integration.kind == "shopify", Integration.shop == shop,
                                                   Integration.active.is_(True)))
        if other is not None:
            raise ShopifyError("This Shopify store is already connected to another CODShield account.")
        integ = Integration(merchant_id=merchant.id, kind="shopify", shop=shop)
        s.add(integ)
    integ.client_id = (client_id or "").strip() or None
    integ.secret_enc = notify.encrypt(client_secret.strip())
    integ.token_enc = notify.encrypt(access_token.strip()) if access_token else None
    integ.token_expires_at = None
    integ.settings = {**DEFAULT_SETTINGS, **(integ.settings or {}), **(options or {})}
    integ.active, integ.last_error = True, None
    s.flush()
    try:
        name = graphql(s, integ, "{ shop { name } }")["shop"]["name"]
        _subscribe(s, integ)
    except ShopifyError:
        s.rollback()
        raise
    integ.stats = {**(integ.stats or {}), "shop_name": name}
    s.commit()
    return integ


def view(integ: Integration) -> dict:
    return {"id": integ.id, "kind": integ.kind, "shop": integ.shop, "active": integ.active,
            "auth": "client credentials" if integ.client_id else "access token",
            "settings": {**DEFAULT_SETTINGS, **(integ.settings or {})}, "stats": integ.stats or {},
            "last_event_at": integ.last_event_at.isoformat() if integ.last_event_at else None,
            "last_error": integ.last_error, "created_at": integ.created_at.isoformat(),
            "webhook_url": f"{settings.PUBLIC_URL}/shopify/webhooks/{integ.id}"}


# ------------------------------------------------------------------ webhooks
def verify(integ: Integration, raw: bytes, signature: str | None) -> bool:
    if not signature:
        return False
    mac = base64.b64encode(hmac.new(notify.decrypt(integ.secret_enc).encode(), raw, hashlib.sha256).digest()).decode()
    return hmac.compare_digest(mac, signature)


def accept(integration_id: int, topic: str, order: dict, webhook_id: str | None) -> None:
    if webhook_id:
        if webhook_id in _seen_webhooks:
            return
        _seen_webhooks.append(webhook_id)
    if SYNC:
        _process(integration_id, topic, order)
    else:
        _pool.submit(_process, integration_id, topic, order)


def _process(integration_id: int, topic: str, order: dict) -> None:
    from .db import SessionLocal
    with SessionLocal() as s:
        integ = s.get(Integration, integration_id)
        if not integ or not integ.active:
            return
        m = s.get(Merchant, integ.merchant_id)
        if not m or not m.active:
            return
        try:
            if topic == "orders/create":
                _on_create(s, integ, m, order)
            elif topic == "orders/updated":
                _on_updated(s, integ, m, order)
            integ.last_error = None
        except Exception as e:                    # recorded for the store to see; never crashes the worker
            log.warning("shopify %s order %s: %s", integ.shop, order.get("id"), e)
            s.rollback()
            integ = s.get(Integration, integration_id)
            integ.last_error = f"{topic} {order.get('name', '')}: {e}"[:500]
        integ.last_event_at = utcnow()
        s.commit()


def is_cod(order: dict) -> bool:
    names = [g.lower() for g in order.get("payment_gateway_names") or []]
    return any("cash on delivery" in g or g in ("cod", "cash_on_delivery") or "(cod)" in g for g in names)


def customer(order: dict) -> dict:
    ship = order.get("shipping_address") or {}
    bill = order.get("billing_address") or {}
    cust = order.get("customer") or {}
    addr = " ".join(x for x in (ship.get("address1"), ship.get("address2")) if x)
    return {"phone": ship.get("phone") or bill.get("phone") or order.get("phone") or cust.get("phone"),
            "email": order.get("email") or order.get("contact_email") or cust.get("email"),
            "address": addr or None, "city": ship.get("city") or bill.get("city"),
            "country": (ship.get("country_code") or bill.get("country_code") or "").upper()}


def _bump(integ: Integration, key: str) -> None:
    st = dict(integ.stats or {})
    st[key] = st.get(key, 0) + 1
    integ.stats = st


def _on_create(s: Session, integ: Integration, m: Merchant, order: dict) -> None:
    from . import auth
    opts = {**DEFAULT_SETTINGS, **(integ.settings or {})}
    if not opts["check_all_orders"] and not is_cod(order):
        return
    who = customer(order)
    if who["country"] not in ("PK", "AE"):
        _bump(integ, "skipped_other_country")
        return
    auth.check_quota(s, m)
    r = service.check_many(s, [who], m)[0]
    if "error" in r:
        _bump(integ, "skipped_no_contact")
        return
    _bump(integ, "checked")
    _bump(integ, f"band_{r['band']}")
    gid = order.get("admin_graphql_api_id") or f"gid://shopify/Order/{order['id']}"
    graphql(s, integ, """mutation($id: ID!, $tags: [String!]!) { tagsAdd(id: $id, tags: $tags) { userErrors { message } } }""",
            {"id": gid, "tags": [f"codshield-{r['band']}", f"codshield-score-{r['score']}"]})
    if opts["add_note"]:
        line = (f"CODShield: {r['band']} risk ({r['score']}/100) - {ACTION_TEXT[r['band']]}."
                + (f" {'; '.join(r['reasons'][:3])}." if r.get("reasons") and m.tier != "score_only" else ""))
        note = ((order.get("note") or "").rstrip() + "\n" + line).strip()
        graphql(s, integ, """mutation($input: OrderInput!) { orderUpdate(input: $input) { userErrors { message } } }""",
                {"input": {"id": gid, "note": note[:5000]}})


def _on_updated(s: Session, integ: Integration, m: Merchant, order: dict) -> None:
    if (m.tier or "contributor") == "score_only" or m.agreement_signed_at is None:
        return
    opts = {**DEFAULT_SETTINGS, **(integ.settings or {})}
    tags = {t.strip().lower() for t in (order.get("tags") or "").split(",") if t.strip()}
    types = {OUTCOME_TAGS[t] for t in tags if t in OUTCOME_TAGS}
    if (opts["auto_delivered"] and is_cod(order) and order.get("financial_status") == "paid"
            and order.get("fulfillment_status") == "fulfilled" and not (types - {"delivered_paid"})):
        types.add("delivered_paid")
    if not types:
        return
    who = customer(order)
    if who["country"] not in ("PK", "AE"):
        return
    when = order.get("updated_at") or order.get("created_at")
    try:
        occurred = datetime.fromisoformat(when.replace("Z", "+00:00")) if when else utcnow()
    except ValueError:
        occurred = utcnow()
    prepared = []
    for typ in sorted(types):
        try:
            prepared.append(service.prepare_event(
                m, order_ref=f"shopify:{order.get('name') or order.get('id')}", type=typ, occurred_at=occurred,
                phone=who["phone"], email=who["email"], address=who["address"], city=who["city"],
                country=who["country"], amount=float(order["total_price"]) if order.get("total_price") else None,
                currency=(order.get("currency") or "")[:3] or None, evidence=f"Shopify order {order.get('name', '')}"))
        except service.ValidationError as e:
            _bump(integ, "outcomes_rejected")
            integ.last_error = f"{order.get('name', '')}: {e}"
    for _, outcome in service.commit_events_bulk(s, m, prepared, source="shopify"):
        _bump(integ, "outcomes_" + outcome)
