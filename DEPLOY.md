# Put CODShield online for free

Total time: about 20 minutes. Three free accounts, no credit card needed for Neon or GitHub.

| Piece | Free service | What it does |
|---|---|---|
| Code | GitHub | Holds the code; runs the hourly agents (GitHub Actions) |
| Database | Neon | Postgres, 1 GB, doesn't expire |
| Website + API | Render | Serves the site at `https://<name>.onrender.com` |

## 1. Make two secrets

Generate two long random strings (a password manager works, or run
`python -c "import secrets;print(secrets.token_urlsafe(48))"` twice).

- **Hash secret**: scrambles phone numbers. Keep it safe and never change it, or every stored record stops matching.
- **Admin key**: the password for the Admin tab.

## 2. Neon (database)

1. Sign up at neon.com and create a project. Pick region **AWS Europe (Frankfurt)**.
2. Copy the **connection string** (starts with `postgresql://`, ends with `sslmode=require`).

## 3. GitHub (code, tests, keep-alive)

Push the code to GitHub. The workflow in `.github/workflows/agents.yml` needs no secrets:

* it runs the tests on every push to `main`;
* every 10 minutes it pings `/health`, so Render's free server doesn't fall asleep (a sleeping server takes
  ~50 seconds to answer the first order check).

The server runs its own housekeeping while it is awake: once a day it deletes outcomes older than the retention
period (730 days), flags disputes open for more than 30 days, lowers the trust of stores whose reports keep being
overturned, and clears expired codes and links. Platform admins can see the last run, or run it now, with
`GET /v1/admin/housekeeping` and `POST /v1/admin/housekeeping/run`.

## 4. Render (website)

1. Sign up at render.com with your GitHub account.
2. New > **Blueprint** > choose the repository. Render reads `render.yaml`.
3. Fill in the three values: `DATABASE_URL`, `CODSHIELD_HASH_SECRET` (same as GitHub), `CODSHIELD_ADMIN_KEY`.
4. Deploy. When it's live, open the URL, go to **Admin**, enter your admin key, and add your first merchant.

## Free-tier limits to know

- Render's free service sleeps after 15 minutes without visits; the next visit takes about a minute to wake it.
  Fine for a pilot. For merchants checking orders live, move to the smallest paid instance.
- Neon free: 1 GB storage per project and compute that pauses when idle (wakes in under a second).
  Hashed records are small; 1 GB holds millions of events.
- Free servers are in Germany. Use test data only until your lawyer confirms where Pakistani and UAE
  customer data may be stored.

## Optional services (all have free tiers)

Set these on Render (Environment) when you're ready. Everything works without them; the fallbacks are noted.

| What | Variables | Without it |
| --- | --- | --- |
| Email: password resets, invitations, dispute notices | `CODSHIELD_MAIL_FROM` plus either SMTP (`CODSHIELD_SMTP_HOST`, `CODSHIELD_SMTP_PORT`, `CODSHIELD_SMTP_USER`, `CODSHIELD_SMTP_PASSWORD`) or `RESEND_API_KEY` | Admins share temporary passwords; "Forgot password" tells people to ask their administrator |
| SMS: dispute verification codes | `TWILIO_ACCOUNT_SID`, `TWILIO_AUTH_TOKEN`, `TWILIO_FROM` (a number, or a Messaging Service SID starting MG) | Disputes arrive "unverified"; a platform admin confirms the phone (for example by calling) before records are frozen |
| Links in emails, Shopify webhooks | `CODSHIELD_PUBLIC_URL` (defaults to `https://codshield-sx1i.onrender.com`) | Default is used |

Free email options: a Gmail address with an app password (`smtp.gmail.com`, port 587), or Brevo's free SMTP
(300 emails a day). Resend needs a domain you own.

## Connecting stores

* **WooCommerce:** Developers tab → Download plugin. Install it in WordPress, then paste a live API key with the
  check and report scopes under WooCommerce → Settings → CODShield.
* **Shopify:** the store creates an app in Shopify's Dev Dashboard with the `read_orders` and `write_orders`
  scopes and installs it on their store, then enters the shop address, client ID and client secret under
  Developers → Connect Shopify. New cash-on-delivery orders are tagged `codshield-high` / `-medium` / `-low`;
  staff report outcomes by tagging orders `cod-refused`, `cod-delivered`, `cod-fake-order` and so on.
