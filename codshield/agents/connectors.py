"""Feed connectors used by the ingestion agent.

Each connector reads delivery outcomes from a source the MERCHANT controls and
has authorised (their own CSV export, their own endpoint, their own Shopify
store) and yields normalized event dicts. Connectors never scrape third-party
sites or collect data a merchant has not contributed.

Secrets (tokens) are never stored in the database: feed_config holds the NAME
of an environment variable, e.g. {"token_env": "MERCHANT_12_TOKEN"}.
"""
import csv
import os
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

import httpx

REQUIRED = ("order_ref", "type", "occurred_at")


def _parse_dt(v: str) -> datetime:
    dt = datetime.fromisoformat(v.replace("Z", "+00:00"))
    if dt.tzinfo:
        dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt


def _clean(row: dict) -> dict:
    out = {k: (row.get(k) or None) for k in
           ("order_ref", "type", "occurred_at", "phone", "email", "address", "city",
            "country", "currency", "evidence")}
    for k in REQUIRED:
        if not out[k]:
            raise ValueError(f"missing {k}")
    out["occurred_at"] = _parse_dt(out["occurred_at"])
    out["type"] = out["type"].strip().lower()
    amt = row.get("amount")
    out["amount"] = float(amt) if amt not in (None, "") else None
    return out


# ---------------------------------------------------------------- CSV drop
def csv_drop(cfg: dict) -> Iterator[dict]:
    """cfg: {"type":"csv","inbox":"/data/feeds/merchant12"}
    Reads *.csv from inbox, moves each file to inbox/processed afterwards."""
    inbox = Path(cfg["inbox"])
    done = inbox / "processed"
    done.mkdir(parents=True, exist_ok=True)
    for f in sorted(inbox.glob("*.csv")):
        with f.open(newline="", encoding="utf-8-sig") as fh:
            for i, row in enumerate(csv.DictReader(fh)):
                try:
                    yield _clean(row)
                except ValueError as e:
                    yield {"_error": f"{f.name} row {i + 2}: {e}"}
        shutil.move(str(f), done / f.name)


# ---------------------------------------------------------------- JSON pull
def json_pull(cfg: dict) -> Iterator[dict]:
    """cfg: {"type":"json","url":"https://merchant.example/api/cod-outcomes",
             "token_env":"MERCHANT_12_TOKEN","cursor":"2026-10-01T00:00:00Z"}
    Expects GET url?since=<cursor> -> {"events":[...], "next_cursor":"..."}"""
    token = os.getenv(cfg.get("token_env", ""), "")
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    params = {"since": cfg["cursor"]} if cfg.get("cursor") else {}
    with httpx.Client(timeout=30) as c:
        r = c.get(cfg["url"], params=params, headers=headers)
        r.raise_for_status()
        data = r.json()
    for row in data.get("events", []):
        try:
            yield _clean(row)
        except ValueError as e:
            yield {"_error": str(e)}
    if data.get("next_cursor"):
        yield {"_cursor": data["next_cursor"]}


# ---------------------------------------------------------------- Shopify
# NOTE: built against Shopify's public Admin REST order fields; test against a
# development store before using with a live merchant.
def _shopify_type(o: dict, rto_tags: set[str]) -> str | None:
    tags = {t.strip().lower() for t in (o.get("tags") or "").split(",") if t.strip()}
    if tags & rto_tags:
        return "refused_at_door"
    if "fake-order" in tags or o.get("cancel_reason") == "fraud":
        return "fake_order"
    if "return-abuse" in tags:
        return "return_abuse"
    gateways = " ".join(o.get("payment_gateway_names") or []).lower()
    is_cod = "cash on delivery" in gateways or "cod" in gateways
    if is_cod and o.get("financial_status") == "paid" and o.get("fulfillment_status") == "fulfilled":
        return "delivered_paid"
    return None


def shopify(cfg: dict) -> Iterator[dict]:
    """cfg: {"type":"shopify","shop":"mystore.myshopify.com","token_env":"SHOP12_TOKEN",
             "api_version":"2025-07","rto_tags":["rto","refused"],"country":"PK",
             "cursor":"2026-10-01T00:00:00Z"}"""
    token = os.environ[cfg["token_env"]]
    version = cfg.get("api_version", "2025-07")
    rto_tags = {t.lower() for t in cfg.get("rto_tags", ["rto", "refused", "returned-to-origin"])}
    url = f"https://{cfg['shop']}/admin/api/{version}/orders.json"
    params = {"status": "any", "limit": 250, "order": "updated_at asc",
              "fields": "id,name,tags,cancel_reason,financial_status,fulfillment_status,"
                        "payment_gateway_names,total_price,currency,updated_at,phone,email,"
                        "shipping_address"}
    if cfg.get("cursor"):
        params["updated_at_min"] = cfg["cursor"]
    last = cfg.get("cursor")
    with httpx.Client(timeout=30, headers={"X-Shopify-Access-Token": token}) as c:
        while url:
            r = c.get(url, params=params)
            r.raise_for_status()
            for o in r.json().get("orders", []):
                last = o.get("updated_at") or last
                t = _shopify_type(o, rto_tags)
                if not t:
                    continue
                addr = o.get("shipping_address") or {}
                yield {
                    "order_ref": str(o.get("name") or o["id"]), "type": t,
                    "occurred_at": _parse_dt(o["updated_at"]),
                    "phone": o.get("phone") or addr.get("phone"), "email": o.get("email"),
                    "address": " ".join(filter(None, [addr.get("address1"), addr.get("address2")])),
                    "city": addr.get("city"), "country": cfg.get("country"),
                    "amount": float(o["total_price"]) if o.get("total_price") else None,
                    "currency": o.get("currency"), "evidence": f"shopify:{o['id']}",
                }
            # cursor pagination via Link header
            url, params = None, None
            for part in r.headers.get("link", "").split(","):
                if 'rel="next"' in part:
                    url = part[part.find("<") + 1:part.find(">")]
    if last:
        yield {"_cursor": last}


CONNECTORS = {"csv": csv_drop, "json": json_pull, "shopify": shopify}
