# CODShield — shared COD & return-abuse risk network (Pakistan + UAE)

**To put it online for free, follow [DEPLOY.md](DEPLOY.md).** The web interface is served at `/`.

Merchants report delivery outcomes (refused at door, fake order, fake address,
return abuse, chargeback, and successful paid deliveries). Before shipping a COD
order, any member merchant calls `/v1/check` and gets a 0–100 risk score, a
band, the reasons, and a recommended action.

Everything here is free and open source: Python, FastAPI, SQLAlchemy, SQLite
(dev) or PostgreSQL (prod), `phonenumbers`.

## Design rules (why big platforms can sign up)

| Rule | How it's enforced in code |
|---|---|
| No raw personal data stored | Phone, email and address are normalized, then HMAC-SHA256 hashed with a secret pepper (`identity.py`). A test checks the DB file contains no raw values. |
| Facts, not "bad intention" labels | Only fixed event types are accepted (`models.EventType`). |
| One merchant can't blacklist someone alone | Score is capped below HIGH until 2+ merchants report (`scoring.py`). |
| Old behaviour fades | Event weight halves every 180 days; events purged after 2 years. |
| Good history counts | `delivered_paid` events lower the score. |
| People can contest | `POST /v1/disputes` freezes their records until an admin resolves it. |
| Contributors are accountable | Reporting requires a signed data-sharing agreement; merchants with many overturned reports are automatically down-weighted. |
| PK + UAE number formats match | `0300-1234567`, `+92 300 1234567`, `923001234567`, `0092…` all match; same for `050…`, `+971…`, `00971…`. |

## Accounts, roles and plans (SaaS)

People sign in with email and password; systems use the store's API key.

| Who | What they can do |
|---|---|
| **Platform admin** (you) | Add and suspend stores, set each store's plan and maker-checker rule, manage any store's users, decide consumer disputes, network report, full activity log. The first one is created on the sign-in page with the server's admin key. |
| **Store user** | Whatever their store admin ticks, in the countries ticked (Pakistan, UAE or both). |

Store permissions: `check` (check orders) · `submit` (maker, single entry) · `upload` (maker, bulk) ·
`approve` (checker) · `reports` · `disputes` (withdraw or confirm records customers contest) ·
`users` (store admin: team, settings, API key, activity log). Templates: Store admin, Maker, Checker,
Call centre agent, Disputes officer, Viewer.

**Maker-checker:** when on (the default), outcomes entered by staff wait in *Approvals* and only count once a
different person approves them. Pending entries hold scrambled identifiers plus a masked contact
(`+92•••••4567`) only. API-key integrations record directly.

**Plans:** Free (3 users, 1,000 checks a month), Growth (25 users, 50,000), Enterprise (unlimited). Limits
are enforced; billing is not built in yet, so plan changes are made by a platform admin.

Every sign-in, entry, approval, user change, key rotation and dispute decision is written to the activity log.

## Run it locally (5 minutes)

```bash
pip install -r requirements.txt
cp .env.example .env            # then set CODSHIELD_HASH_SECRET and CODSHIELD_ADMIN_KEY
export $(grep -v '^#' .env | xargs)
uvicorn codshield.api:app --reload
# interactive docs: http://localhost:8000/docs
pytest -q                       # 26 tests
```

Production database (free, self-hosted): `docker compose up -d db`, then set
`CODSHIELD_DATABASE_URL=postgresql+psycopg://codshield:codshield@localhost:5432/codshield`
and `pip install "psycopg[binary]"`.

## API

All merchant calls send `X-API-Key`. Admin calls send `X-Admin-Key`.

| Method | Path | Who | Purpose |
|---|---|---|---|
| POST | `/v1/admin/merchants` | admin | Onboard merchant, returns API key once |
| POST | `/v1/check` | merchant | Risk score for phone / email / address |
| POST | `/v1/events` | merchant | Report one delivery outcome |
| POST | `/v1/events/batch` | merchant | Up to 1000 outcomes |
| POST | `/v1/disputes` | public | Consumer contests records on their number |
| GET | `/v1/admin/disputes` | admin | Review queue |
| POST | `/v1/admin/disputes/{id}/resolve` | admin | Uphold (remove) or reject (restore) |

Example check response:

```json
{"score": 58, "band": "medium", "recommended_action": "confirm_by_call_or_otp",
 "reasons": ["1 x refused_at_door", "1 x fake_order", "reported by 2 merchant(s)"],
 "reporting_merchants": 2, "paid_deliveries": 0, "matched_on": ["phone"]}
```

Bands: `low` → ship normally · `medium` → confirm by call/OTP · `high` → require prepayment or partial advance.

Event types: `refused_at_door`, `unreachable`, `fake_address`, `fake_order`,
`return_abuse`, `chargeback`, `delivered_paid`.

## Agents (keep the database updated)

```bash
python -m codshield.agents run            # one pass
python -m codshield.agents run --loop     # every hour (use --interval N)
```

Or schedule with cron (free): `0 * * * * cd /opt/codshield && python -m codshield.agents run`

**Ingest agent** — for every merchant with a `feed_config` and a signed agreement,
pulls their outcomes, validates, de-duplicates (`merchant + order_ref + type`),
records them, and saves a cursor so the next run only fetches new data.

| Connector | `feed_config` example |
|---|---|
| CSV drop folder | `{"type":"csv","inbox":"/data/feeds/m12"}` — see `samples/outcomes.csv` |
| Merchant JSON endpoint | `{"type":"json","url":"https://merchant/api/cod-outcomes","token_env":"M12_TOKEN"}` — expects `GET ?since=<cursor>` → `{"events":[...],"next_cursor":"..."}` |
| Shopify (merchant's own store) | `{"type":"shopify","shop":"x.myshopify.com","token_env":"SHOP12_TOKEN","country":"PK","rto_tags":["rto","refused"]}` — maps RTO tags, fraud cancellations and paid COD orders. Test on a Shopify development store first. |

Tokens live in environment variables, never in the database.

**Maintenance agent** — purges expired events and orphaned hashes, lists disputes
open > 30 days, and halves the trust weight of merchants with ≥ 50 reports where
> 20% were overturned on dispute.

Agents only read data the merchant contributes from systems they control. There
is deliberately no scraper.

## Before going live — checklist

- [ ] Legal review in both countries: UAE PDPL (mainland; DIFC/ADGM differ), whether the
      service touches credit-information rules; Pakistan PECA and the pending data protection bill.
- [ ] Data-sharing agreement template for contributing merchants.
- [ ] Merchants add a line to their privacy policy disclosing fraud-prevention sharing.
- [ ] Public page explaining the service and linking the dispute form.
- [ ] Generate a long random `CODSHIELD_HASH_SECRET`, store it in a secrets manager, never rotate casually.
- [ ] Host Pakistan data in Pakistan, UAE data in the UAE (draft PK law localizes "critical" data).
- [ ] HTTPS in front (Caddy or Nginx + Let's Encrypt, both free).
- [ ] Swap in-memory rate limiting for Redis when running more than one instance.

## Project layout

```
codshield/
  config.py      settings from env
  models.py      schema (merchants, identities, events, disputes, agent_runs)
  identity.py    PK/UAE phone, email, address normalization + HMAC hashing
  scoring.py     decay, corroboration cap, bands
  service.py     report / check / dispute logic
  api.py         FastAPI app
  agents/        connectors.py (csv, json, shopify), runner.py (ingest, maintenance)
tests/test_all.py
render.yaml    free hosting blueprint (see DEPLOY.md)
.github/       hourly agents on GitHub Actions
```
