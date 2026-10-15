"""Generate synthetic CODShield test data (no real people).

    python testdata/generate.py            # writes into testdata/out/

Outputs
  outcomes_part1..5.csv      1,000 outcomes each, for the web app's "Upload outcomes in bulk" (max 1,000 rows per upload)
  outcomes_all.csv           all 5,000 outcomes in one file (Postman Collection Runner data file)
  outcomes_batch1..5.json    1,000 outcomes each, body for POST /v1/events/batch
  checks_500.csv / .json     500 customers to score, for "Check orders" upload and POST /v1/check/batch
  invalid_rows.csv / .json   14 rows a batch must reject one by one (bad type, phone, date...)
  invalid_schema.json        9 single bodies that must get HTTP 422 (send one at a time to POST /v1/events)
  customers.csv              who is who: the risk profile each synthetic customer was generated with

Every order_ref starts with TEST- so the data can be removed with:
    python -m codshield.testdata purge
"""
import csv
import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

SEED = 20261015
TOTAL = 5000
OUT = Path(__file__).parent / "out"

PK_CITIES = ["Karachi", "Lahore", "Islamabad", "Rawalpindi", "Faisalabad", "Multan", "Peshawar",
             "Quetta", "Sialkot", "Gujranwala", "Hyderabad", "Abbottabad"]
AE_CITIES = ["Dubai", "Abu Dhabi", "Sharjah", "Ajman", "Al Ain", "Ras Al Khaimah", "Fujairah"]
PK_AREAS = ["DHA Phase 5", "Gulberg III", "Johar Town", "Bahria Town", "Model Town", "Clifton Block 4",
            "G-11/2", "F-7 Markaz", "Satellite Town", "Cantt", "Gulshan-e-Iqbal Block 13", "Hayatabad Phase 3"]
AE_AREAS = ["Al Nahda 2", "Deira Al Muraqqabat", "JLT Cluster D", "Al Barsha 1", "Muwaileh", "Al Khalidiya",
            "Al Majaz 3", "International City", "Al Rashidiya", "Mussafah Shabiya 10"]
PK_COURIERS = ["TCS", "Leopards", "M&P", "PostEx", "Trax", "BlueEx"]
AE_COURIERS = ["Aramex", "Emirates Post", "Fetchr", "Shipa", "Quiqup"]
EMAIL_DOMAINS = ["gmail.com", "yahoo.com", "hotmail.com", "outlook.com"]
FIRST = ["ali", "ahmed", "sara", "fatima", "usman", "ayesha", "bilal", "hina", "omar", "zainab", "hamza",
         "maryam", "faisal", "noor", "imran", "sana", "khalid", "rashid", "aisha", "yousuf"]

# Customer profiles: share of customers, and the outcome mix each one tends to produce.
PROFILES = {
    "good":          (0.62, {"delivered_paid": 0.92, "unreachable": 0.06, "refused_at_door": 0.02}),
    "occasional":    (0.20, {"delivered_paid": 0.60, "refused_at_door": 0.20, "unreachable": 0.15, "return_abuse": 0.05}),
    "serial_refuser": (0.10, {"refused_at_door": 0.55, "unreachable": 0.20, "fake_address": 0.10, "delivered_paid": 0.15}),
    "fraudster":     (0.05, {"fake_order": 0.45, "fake_address": 0.30, "refused_at_door": 0.15, "chargeback": 0.10}),
    "return_abuser": (0.03, {"return_abuse": 0.65, "chargeback": 0.20, "delivered_paid": 0.15}),
}
# How many orders each profile places (bad actors order more often).
ORDERS = {"good": (1, 5), "occasional": (2, 6), "serial_refuser": (4, 12), "fraudster": (3, 10), "return_abuser": (3, 9)}

COLUMNS = ["order_ref", "type", "occurred_at", "phone", "email", "address", "city", "country",
           "amount", "currency", "evidence"]


def phone(rng, country):
    # Mobile-format numbers in a narrow, sequential test block. They are synthetic, but a valid-looking
    # number can still belong to someone: load these only with a cs_test_ key, on a test branch, or purge after.
    if country == "PK":
        return f"03{rng.choice(['00', '01', '21', '33', '45'])}{rng.randint(1000000, 9999999)}"
    return f"05{rng.choice(['0', '2', '5', '6', '8'])}{rng.randint(1000000, 9999999)}"


def make_customers(rng, n=1200):
    names = list(PROFILES)
    weights = [PROFILES[p][0] for p in names]
    seen, out = set(), []
    while len(out) < n:
        country = "PK" if rng.random() < 0.7 else "AE"
        ph = phone(rng, country)
        if ph in seen:
            continue
        seen.add(ph)
        prof = rng.choices(names, weights)[0]
        city = rng.choice(PK_CITIES if country == "PK" else AE_CITIES)
        area = rng.choice(PK_AREAS if country == "PK" else AE_AREAS)
        addr = (f"House {rng.randint(1, 450)}, Street {rng.randint(1, 60)}, {area}" if country == "PK"
                else f"Flat {rng.randint(101, 2405)}, Building {rng.randint(1, 90)}, {area}")
        email = f"{rng.choice(FIRST)}.{rng.randint(10, 9999)}.test@{rng.choice(EMAIL_DOMAINS)}" if rng.random() < 0.45 else ""
        out.append({"phone": ph, "email": email, "address": addr if rng.random() < 0.6 else "", "city": city,
                    "country": country, "profile": prof})
    return out


def make_outcomes(rng, customers):
    now = datetime.now(timezone.utc).replace(microsecond=0)
    rows = []
    while len(rows) < TOTAL:
        c = rng.choice(customers)
        lo, hi = ORDERS[c["profile"]]
        for _ in range(rng.randint(lo, hi)):
            if len(rows) >= TOTAL:
                break
            mix = PROFILES[c["profile"]][1]
            typ = rng.choices(list(mix), list(mix.values()))[0]
            when = now - timedelta(days=rng.randint(1, 360), hours=rng.randint(0, 23), minutes=rng.randint(0, 59))
            pk = c["country"] == "PK"
            amount = rng.randint(15, 250) * 100 if pk else rng.randint(4, 150) * 10
            courier = rng.choice(PK_COURIERS if pk else AE_COURIERS)
            rows.append({
                "order_ref": f"TEST-{'PK' if pk else 'AE'}-{len(rows) + 100001}",
                "type": typ,
                "occurred_at": when.isoformat().replace("+00:00", "Z"),
                "phone": c["phone"], "email": c["email"], "address": c["address"], "city": c["city"],
                "country": c["country"], "amount": amount, "currency": "PKR" if pk else "AED",
                "evidence": f"{courier} CN {rng.randint(10_000_000, 99_999_999)}",
            })
    rows.sort(key=lambda r: r["occurred_at"])
    return rows


def invalid_rows(rng):
    base = {"order_ref": "TEST-BAD-{}", "type": "refused_at_door", "occurred_at": "2026-09-01T10:00:00Z",
            "phone": "03001234567", "email": "", "address": "", "city": "Lahore", "country": "PK",
            "amount": 2500, "currency": "PKR", "evidence": ""}
    # Pass the JSON schema but break a business rule -> rejected row by row inside a batch.
    cases = [
        ("type", "not_a_type"), ("type", "REFUSED"), ("type", "delivered"), ("type", "fraud"),
        ("phone", "12345"), ("phone", "abc"), ("phone", "0300"), ("phone", "0000000000"),
        ("phone", "0300123"), ("phone", "+971 4 000"), ("phone", ""), ("email", "not-an-email"),
        ("occurred_at", "2099-01-01T00:00:00Z"), ("occurred_at", "2020-01-01T00:00:00Z"),
    ]
    out = []
    for i, (field, value) in enumerate(cases, 1):
        r = dict(base, order_ref=f"TEST-BAD-{i:03d}")
        if field == "email":
            r["phone"] = ""      # email-only row with a bad email -> no valid identifier
        r[field] = value
        r["_expected_problem"] = f"{field} = {value[:30]!s}"
        out.append(r)
    return out


def write_csv(path, rows, cols):
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)


def as_json(r):
    out = {k: v for k, v in r.items() if k in COLUMNS and v not in ("", None)}
    if isinstance(out.get("amount"), str):
        try:
            out["amount"] = float(out["amount"])
        except ValueError:
            pass
    return out


def main():
    rng = random.Random(SEED)
    OUT.mkdir(exist_ok=True)
    customers = make_customers(rng)
    rows = make_outcomes(rng, customers)

    write_csv(OUT / "outcomes_all.csv", rows, COLUMNS)
    for i in range(5):
        part = rows[i * 1000:(i + 1) * 1000]
        write_csv(OUT / f"outcomes_part{i + 1}.csv", part, COLUMNS)
        (OUT / f"outcomes_batch{i + 1}.json").write_text(json.dumps([as_json(r) for r in part], indent=1))

    # 500 customers to check: mostly ones with history, some brand new.
    picks = rng.sample(customers, 450) + make_customers(random.Random(SEED + 1), 50)
    rng.shuffle(picks)
    checks = [{"order_ref": f"TEST-CHK-{i:04d}", **{k: c[k] for k in ("phone", "email", "address", "city", "country")}}
              for i, c in enumerate(picks, 1)]
    write_csv(OUT / "checks_500.csv", checks, ["order_ref", "phone", "email", "address", "city", "country"])
    (OUT / "checks_500.json").write_text(json.dumps(
        [{k: v for k, v in c.items() if k != "order_ref" and v} for c in checks], indent=1))

    bad = invalid_rows(rng)
    ok = as_json(rows[0]) | {"order_ref": "TEST-SCHEMA"}
    schema = [ok | {"country": "IN"}, ok | {"country": "pakistan"}, ok | {"currency": "PKRS"},
              ok | {"order_ref": "X" * 120}, ok | {"evidence": "E" * 600}, ok | {"amount": "lots"},
              ok | {"occurred_at": "yesterday"}, {k: v for k, v in ok.items() if k != "type"},
              {k: v for k, v in ok.items() if k != "order_ref"}]
    (OUT / "invalid_schema.json").write_text(json.dumps(schema, indent=1))
    write_csv(OUT / "invalid_rows.csv", bad, COLUMNS + ["_expected_problem"])
    (OUT / "invalid_rows.json").write_text(json.dumps([as_json(r) for r in bad], indent=1))
    write_csv(OUT / "customers.csv", customers, ["phone", "email", "address", "city", "country", "profile"])

    from collections import Counter
    print("outcomes:", len(rows), dict(Counter(r["type"] for r in rows)))
    print("countries:", dict(Counter(r["country"] for r in rows)))
    print("customers:", len(customers), dict(Counter(c["profile"] for c in customers)))
    print("written to", OUT)


if __name__ == "__main__":
    main()
