"""Users, sessions, permissions and plans (the SaaS layer).

Three ways to call the API, all resolved to one `Actor`:
  * Bearer session token  -> a person who logged in (tenant user or platform admin)
  * X-API-Key             -> a merchant's system integration (check + direct submit)
  * X-Admin-Key           -> the bootstrap platform key from the server's environment
"""
import base64
import hashlib
import hmac
import secrets
from dataclasses import dataclass, field
from datetime import timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .models import (ALL_PERMS, AuditLog, CheckLog, Merchant, Perm, User,
                     UserSession, utcnow)

SESSION_HOURS = 12
COUNTRIES = ("PK", "AE")

# Plan limits: seats = active users per tenant, checks = order checks per calendar month.
PLANS = {
    "free":       {"label": "Free",       "seats": 3,    "checks": 1_000},
    "growth":     {"label": "Growth",     "seats": 25,   "checks": 50_000},
    "enterprise": {"label": "Enterprise", "seats": None, "checks": None},
}


class AuthError(Exception):
    def __init__(self, status: int, msg: str):
        super().__init__(msg)
        self.status = status


# ------------------------------------------------------------------ passwords
def hash_password(pw: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.scrypt(pw.encode(), salt=salt, n=2 ** 14, r=8, p=1, dklen=32)
    return "scrypt$" + base64.b64encode(salt).decode() + "$" + base64.b64encode(dk).decode()


def verify_password(pw: str, stored: str) -> bool:
    try:
        _, salt_b64, dk_b64 = stored.split("$")
        dk = hashlib.scrypt(pw.encode(), salt=base64.b64decode(salt_b64), n=2 ** 14, r=8, p=1, dklen=32)
        return hmac.compare_digest(dk, base64.b64decode(dk_b64))
    except Exception:
        return False


def check_password_strength(pw: str) -> None:
    if len(pw) < 10:
        raise AuthError(422, "Use a password of at least 10 characters.")


def temp_password() -> str:
    return secrets.token_urlsafe(9)


# ------------------------------------------------------------------ sessions
def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def create_session(s: Session, user: User) -> str:
    token = "sess_" + secrets.token_urlsafe(32)
    s.add(UserSession(user_id=user.id, token_hash=_token_hash(token),
                      expires_at=utcnow() + timedelta(hours=SESSION_HOURS)))
    user.last_login_at = utcnow()
    s.commit()
    return token


def end_session(s: Session, token: str) -> None:
    sess = s.scalar(select(UserSession).where(UserSession.token_hash == _token_hash(token)))
    if sess:
        s.delete(sess)
        s.commit()


def end_all_sessions(s: Session, user_id: int) -> None:
    s.query(UserSession).filter(UserSession.user_id == user_id).delete()
    s.commit()


def user_for_token(s: Session, token: str) -> User | None:
    sess = s.scalar(select(UserSession).where(UserSession.token_hash == _token_hash(token)))
    if not sess or sess.expires_at < utcnow():
        return None
    u = s.get(User, sess.user_id)
    if not u or not u.active:
        return None
    if u.merchant_id is not None:
        m = s.get(Merchant, u.merchant_id)
        if not m or not m.active:
            return None
    return u


# ------------------------------------------------------------------ actor
@dataclass
class Actor:
    kind: str                         # user / api_key / admin_key
    perms: set = field(default_factory=set)
    countries: set = field(default_factory=lambda: set(COUNTRIES))
    merchant: Merchant | None = None
    user: User | None = None
    is_platform: bool = False
    api_key_id: int | None = None      # 0 = original store key
    mode: str = "live"                 # live / test (sandbox)

    @property
    def label(self) -> str:
        if self.user:
            return f"user:{self.user.email}"
        if self.kind == "api_key" and self.api_key_id:
            return f"api-key:{self.api_key_id}"
        return self.kind.replace("_", "-")

    def require(self, perm: str) -> None:
        if self.is_platform and perm != "tenant":
            return
        if perm not in self.perms:
            if self.kind == "api_key":
                need = next((sc for sc, ps in SCOPE_PERMS.items() if perm in ps), perm)
                if self.merchant is not None and (self.merchant.tier or "contributor") == "score_only" and perm in CONTRIBUTOR_ONLY:
                    raise AuthError(403, "Score-only stores can check orders but not report outcomes.")
                raise AuthError(403, f"This API key doesn't have the '{need}' scope.")
            if self.merchant is not None and (self.merchant.tier or "contributor") == "score_only" and perm in CONTRIBUTOR_ONLY:
                raise AuthError(403, "Your store is on the score-only tier, which doesn't include reporting outcomes.")
            raise AuthError(403, f"Your role doesn't include '{perm}' access. Ask your administrator.")

    def require_tenant(self) -> Merchant:
        if not self.merchant:
            raise AuthError(403, "This action belongs to a store account. Sign in as a store user.")
        return self.merchant

    def require_country(self, country: str) -> None:
        if country not in self.countries:
            names = {"PK": "Pakistan", "AE": "the UAE"}
            raise AuthError(403, f"Your account isn't set up for {names.get(country, country)}.")

    def require_platform(self) -> None:
        if not self.is_platform:
            raise AuthError(403, "Only platform administrators can do this.")


CONTRIBUTOR_ONLY = {Perm.SUBMIT.value, Perm.UPLOAD.value, Perm.APPROVE.value, Perm.DISPUTES.value}
SCOPE_PERMS = {"check": {Perm.CHECK.value}, "report": {Perm.SUBMIT.value, Perm.UPLOAD.value},
               "read": {Perm.REPORTS.value}}


def _tier_filter(m: Merchant | None, perms: set) -> set:
    return perms - CONTRIBUTOR_ONLY if m is not None and (m.tier or "contributor") == "score_only" else perms


def actor_for_user(s: Session, u: User) -> Actor:
    perms = set(ALL_PERMS) if u.is_platform_admin else set(filter(None, u.perms.split(",")))
    countries = set(COUNTRIES) if u.is_platform_admin else set(filter(None, u.countries.split(",")))
    m = s.get(Merchant, u.merchant_id) if u.merchant_id else None
    return Actor("user", _tier_filter(m, perms), countries, m, u, u.is_platform_admin)


def actor_for_api_key(m: Merchant, key=None) -> Actor:
    """System integration. A scoped key gets only its scopes; the original store key gets check+report+read."""
    scopes = [x for x in key.scopes.split(",") if x] if key is not None else ["check", "report", "read"]
    perms = set().union(*(SCOPE_PERMS[x] for x in scopes if x in SCOPE_PERMS))
    return Actor("api_key", _tier_filter(m, perms), set(COUNTRIES), m, None, False,
                 api_key_id=key.id if key is not None else 0, mode=key.mode if key is not None else "live")


def actor_for_admin_key() -> Actor:
    return Actor("admin_key", set(ALL_PERMS), set(COUNTRIES), None, None, True)


# ------------------------------------------------------------------ users
def normalize_perms(perms) -> str:
    bad = [p for p in perms if p not in ALL_PERMS]
    if bad:
        raise AuthError(422, f"Unknown permission(s): {', '.join(bad)}")
    return ",".join(p for p in ALL_PERMS if p in set(perms))


def normalize_countries(countries) -> str:
    c = [x.upper() for x in countries]
    if not c or any(x not in COUNTRIES for x in c):
        raise AuthError(422, "Countries must be PK, AE or both.")
    return ",".join(x for x in COUNTRIES if x in c)


def seats_used(s: Session, merchant_id: int) -> int:
    return s.scalar(select(func.count(User.id)).where(User.merchant_id == merchant_id, User.active.is_(True))) or 0


def check_seat_available(s: Session, m: Merchant) -> None:
    limit = PLANS.get(m.plan or "free", PLANS["free"])["seats"]
    if limit is not None and seats_used(s, m.id) >= limit:
        raise AuthError(402, f"Your {PLANS[m.plan or 'free']['label']} plan includes {limit} users. "
                             "Deactivate a user or upgrade the plan.")


def checks_this_month(s: Session, merchant_id: int) -> int:
    start = utcnow().replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    return s.scalar(select(func.count(CheckLog.id)).where(CheckLog.merchant_id == merchant_id,
                                                          CheckLog.created_at >= start)) or 0


def check_quota(s: Session, m: Merchant, n: int = 1) -> None:
    limit = PLANS.get(m.plan or "free", PLANS["free"])["checks"]
    if limit is not None and checks_this_month(s, m.id) + n > limit:
        raise AuthError(402, f"This month's {limit:,} order checks on the {PLANS[m.plan or 'free']['label']} "
                             "plan are used up. Upgrade the plan to keep checking.")


def create_user(s: Session, *, merchant: Merchant | None, email: str, name: str, perms, countries,
                is_platform_admin: bool = False, password: str | None = None) -> tuple[User, str | None]:
    email = email.strip().lower()
    if "@" not in email or "." not in email.split("@")[-1]:
        raise AuthError(422, "Enter a valid email address.")
    if s.scalar(select(User.id).where(func.lower(User.email) == email)):
        raise AuthError(409, "A user with that email already exists.")
    if merchant is not None:
        check_seat_available(s, merchant)
    temp = None
    if password is None:
        password = temp = temp_password()
    else:
        check_password_strength(password)
    u = User(merchant_id=merchant.id if merchant else None, email=email, name=name.strip() or email,
             password_hash=hash_password(password), perms=normalize_perms(perms),
             countries=normalize_countries(countries), is_platform_admin=is_platform_admin,
             must_change_password=temp is not None)
    s.add(u)
    s.commit()
    return u, temp


def public_user(u: User) -> dict:
    return {"id": u.id, "email": u.email, "name": u.name, "merchant_id": u.merchant_id,
            "perms": [p for p in u.perms.split(",") if p] if not u.is_platform_admin else ALL_PERMS,
            "countries": [c for c in u.countries.split(",") if c],
            "is_platform_admin": u.is_platform_admin, "active": u.active,
            "must_change_password": u.must_change_password,
            "last_login_at": u.last_login_at.isoformat() if u.last_login_at else None,
            "created_at": u.created_at.isoformat() if u.created_at else None}


# ------------------------------------------------------------------ audit
def audit(s: Session, actor: Actor | None, action: str, detail: str = "", merchant_id: int | None = None,
          commit: bool = True) -> None:
    s.add(AuditLog(merchant_id=merchant_id if merchant_id is not None else (actor.merchant.id if actor and actor.merchant else None),
                   user_id=actor.user.id if actor and actor.user else None,
                   actor=actor.label if actor else "public", action=action, detail=detail[:2000]))
    if commit:
        s.commit()


# ------------------------------------------------------------------ password links (reset / invite)
RESET_HOURS, INVITE_HOURS = 1, 72


def create_password_link(s: Session, user: User, purpose: str) -> str:
    """A single-use link; only its hash is stored. purpose: reset (1 hour) or invite (72 hours)."""
    from .config import settings
    from .models import PasswordToken
    token = "pw_" + secrets.token_urlsafe(32)
    hours = RESET_HOURS if purpose == "reset" else INVITE_HOURS
    s.add(PasswordToken(user_id=user.id, token_hash=_token_hash(token), purpose=purpose,
                        expires_at=utcnow() + timedelta(hours=hours)))
    s.commit()
    return f"{settings.PUBLIC_URL}/#{'reset' if purpose == 'reset' else 'invite'}={token}"


def use_password_link(s: Session, token: str, new_password: str) -> User:
    from .models import PasswordToken
    pt = s.scalar(select(PasswordToken).where(PasswordToken.token_hash == _token_hash(token or "")))
    if not pt or pt.used_at or pt.expires_at < utcnow():
        raise AuthError(400, "This link has expired or was already used. Ask for a new one.")
    u = s.get(User, pt.user_id)
    if not u or not u.active:
        raise AuthError(400, "This account is switched off. Ask your administrator.")
    check_password_strength(new_password)
    u.password_hash, u.must_change_password = hash_password(new_password), False
    pt.used_at = utcnow()
    # any other open links for this user stop working too
    for other in s.scalars(select(PasswordToken).where(PasswordToken.user_id == u.id, PasswordToken.used_at.is_(None))):
        other.used_at = utcnow()
    s.commit()
    end_all_sessions(s, u.id)
    return u


def send_invite(s: Session, user: User, invited_by: str = "") -> bool:
    """Email a new user a link to choose their own password. False when email isn't set up."""
    from . import notify
    if not notify.mail_enabled():
        return False
    link = create_password_link(s, user, "invite")
    store = ""
    if user.merchant_id:
        m = s.get(Merchant, user.merchant_id)
        store = f" for {m.name}" if m else ""
    return notify.send_mail(user.email, f"Your CODShield account{store}",
                            f"Hello {user.name},\n\n{invited_by or 'An administrator'} has set up a CODShield account"
                            f"{store} for you.\n\nChoose your password here (the link works once, for 72 hours):\n{link}\n\n"
                            "Then sign in with this email address.\n\nCODShield")
