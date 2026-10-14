"""Normalize and hash customer identifiers (Pakistan + UAE aware).

The same customer typed differently ("0300-1234567", "+92 300 1234567",
"923001234567") must produce the same hash, otherwise the network can't match.
"""
import hashlib
import hmac
import re
import unicodedata

import phonenumbers

from .config import settings

SUPPORTED = {"PK", "AE"}


def normalize_phone(raw: str, country: str) -> str | None:
    """Return E.164 (+923001234567 / +971501234567) or None if invalid."""
    if not raw:
        return None
    region = country.upper() if country and country.upper() in SUPPORTED else None
    cleaned = raw.strip()
    # common local habits: "0092..." / "00971..."
    if cleaned.startswith("00"):
        cleaned = "+" + cleaned[2:]
    # "923001234567" / "971501234567" without plus
    digits = re.sub(r"\D", "", cleaned)
    if not cleaned.startswith("+") and (digits.startswith("92") and len(digits) == 12
                                         or digits.startswith("971") and len(digits) == 12):
        cleaned = "+" + digits
    try:
        num = phonenumbers.parse(cleaned, region)
    except phonenumbers.NumberParseException:
        return None
    if not phonenumbers.is_valid_number(num):
        return None
    return phonenumbers.format_number(num, phonenumbers.PhoneNumberFormat.E164)


def normalize_email(raw: str) -> str | None:
    if not raw or "@" not in raw:
        return None
    local, _, domain = raw.strip().lower().partition("@")
    local = local.split("+", 1)[0]                     # drop +tags
    if domain in ("gmail.com", "googlemail.com"):
        local = local.replace(".", "")
        domain = "gmail.com"
    if not local or "." not in domain:
        return None
    return f"{local}@{domain}"


_ADDR_SYNONYMS = {
    "st": "street", "rd": "road", "blk": "block", "bldg": "building", "apt": "apartment",
    "flt": "flat", "no": "number", "ph": "phase", "sec": "sector", "nr": "near",
}


def normalize_address(raw: str, city: str | None) -> str | None:
    if not raw:
        return None
    text = unicodedata.normalize("NFKC", f"{raw} {city or ''}").lower()
    text = re.sub(r"[^\w\s]", " ", text)
    tokens = [_ADDR_SYNONYMS.get(t, t) for t in text.split()]
    out = " ".join(tokens)
    return out if len(out) >= 8 else None


def keyed_hash(kind: str, value: str) -> str:
    msg = f"{kind}:{value}".encode()
    return hmac.new(settings.HASH_SECRET.encode(), msg, hashlib.sha256).hexdigest()


def identifiers(phone: str | None, email: str | None, address: str | None,
                city: str | None, country: str) -> list[tuple[str, str]]:
    """Return [(kind, hash)] for whatever identifiers are valid."""
    out = []
    if (p := normalize_phone(phone or "", country)):
        out.append(("phone", keyed_hash("phone", p)))
    if (e := normalize_email(email or "")):
        out.append(("email", keyed_hash("email", e)))
    if (a := normalize_address(address or "", city)):
        out.append(("address", keyed_hash("address", a)))
    return out
