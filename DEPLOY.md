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

## 3. GitHub (code + agents)

1. Push this folder to a new **private** repository.
2. In the repo: Settings > Secrets and variables > Actions > New secret. Add:
   - `DATABASE_URL` = the Neon connection string
   - `CODSHIELD_HASH_SECRET` = your hash secret
3. Actions tab > **agents** > Run workflow, to check it works. After that it runs every hour.

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
