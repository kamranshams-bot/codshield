"""Runtime settings, read from environment variables (see .env.example)."""
import os


class Settings:
    # SQLite by default (free, zero setup). Switch to Postgres in production:
    # postgresql+psycopg://user:pass@host:5432/codshield
    DATABASE_URL: str = os.getenv("CODSHIELD_DATABASE_URL") or os.getenv("DATABASE_URL") or "sqlite:///./codshield.db"
    # Hosts like Neon/Render hand out postgres:// or postgresql:// URLs; use the psycopg 3 driver.
    for _p in ("postgres://", "postgresql://"):
        if DATABASE_URL.startswith(_p):
            DATABASE_URL = "postgresql+psycopg://" + DATABASE_URL[len(_p):]

    # Secret "pepper" for HMAC hashing of phone/email/address.
    # MUST be set to a long random value in production and never changed
    # (changing it makes every stored hash unmatchable).
    HASH_SECRET: str = os.getenv("CODSHIELD_HASH_SECRET", "dev-only-change-me")

    # Admin key for /v1/admin/* endpoints.
    ADMIN_KEY: str = os.getenv("CODSHIELD_ADMIN_KEY", "dev-admin-key")

    # Scoring
    HALF_LIFE_DAYS: float = float(os.getenv("CODSHIELD_HALF_LIFE_DAYS", "180"))
    RETENTION_DAYS: int = int(os.getenv("CODSHIELD_RETENTION_DAYS", "730"))  # 2 years

    # Simple per-key rate limit (requests per minute)
    RATE_LIMIT_PER_MIN: int = int(os.getenv("CODSHIELD_RATE_LIMIT", "600"))


settings = Settings()
