"""Outbound email and SMS, plus encryption for stored third-party secrets.

Both channels are optional: with nothing configured, `mail_enabled()` / `sms_enabled()` are False and
callers fall back (admins hand out reset links; disputes wait for a manual check)."""
import base64
import hashlib
import logging
import os
import smtplib
from email.message import EmailMessage

import httpx

from .config import settings

log = logging.getLogger("codshield")
SENT: list[dict] = []          # tests read what would have been sent
TEST_MODE = os.getenv("CODSHIELD_NOTIFY_TEST") == "1"   # tests: record instead of sending


# ------------------------------------------------------------------ email
def mail_enabled() -> bool:
    return TEST_MODE or bool(settings.MAIL_FROM and (settings.SMTP_HOST or settings.RESEND_API_KEY))


def send_mail(to: str, subject: str, text: str) -> bool:
    if not mail_enabled():
        log.warning("email not configured; not sent: %s to %s", subject, to)
        return False
    if TEST_MODE:
        SENT.append({"channel": "email", "to": to, "subject": subject, "text": text})
        return True
    try:
        if settings.RESEND_API_KEY:
            r = httpx.post("https://api.resend.com/emails", timeout=10,
                           headers={"Authorization": f"Bearer {settings.RESEND_API_KEY}"},
                           json={"from": settings.MAIL_FROM, "to": [to], "subject": subject, "text": text})
            r.raise_for_status()
        else:
            msg = EmailMessage()
            msg["From"], msg["To"], msg["Subject"] = settings.MAIL_FROM, to, subject
            msg.set_content(text)
            if settings.SMTP_PORT == 465:
                with smtplib.SMTP_SSL(settings.SMTP_HOST, 465, timeout=15) as smtp:
                    smtp.login(settings.SMTP_USER, settings.SMTP_PASSWORD)
                    smtp.send_message(msg)
            else:
                with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT, timeout=15) as smtp:
                    smtp.starttls()
                    if settings.SMTP_USER:
                        smtp.login(settings.SMTP_USER, settings.SMTP_PASSWORD)
                    smtp.send_message(msg)
        return True
    except Exception as e:                       # never let email failure break the request
        log.error("email to %s failed: %s", to, e)
        return False


# ------------------------------------------------------------------ SMS
def sms_enabled() -> bool:
    return TEST_MODE or settings.SMS_LOG_ONLY or bool(
        settings.TWILIO_ACCOUNT_SID and settings.TWILIO_AUTH_TOKEN and settings.TWILIO_FROM)


def send_sms(to_e164: str, text: str) -> bool:
    if TEST_MODE or settings.SMS_LOG_ONLY:
        SENT.append({"channel": "sms", "to": to_e164, "text": text})
        if settings.SMS_LOG_ONLY:
            log.warning("SMS (log only) to %s: %s", to_e164, text)
        return True
    if not sms_enabled():
        return False
    sender = {"MessagingServiceSid": settings.TWILIO_FROM} if settings.TWILIO_FROM.startswith("MG") \
        else {"From": settings.TWILIO_FROM}
    try:
        r = httpx.post(f"https://api.twilio.com/2010-04-01/Accounts/{settings.TWILIO_ACCOUNT_SID}/Messages.json",
                       auth=(settings.TWILIO_ACCOUNT_SID, settings.TWILIO_AUTH_TOKEN), timeout=10,
                       data={"To": to_e164, "Body": text, **sender})
        r.raise_for_status()
        return True
    except Exception as e:
        log.error("SMS to %s failed: %s", to_e164[:6] + "…", e)
        return False


# ------------------------------------------------------------------ secrets at rest
def _fernet():
    from cryptography.fernet import Fernet
    key = hashlib.sha256(("codshield-secrets:" + settings.HASH_SECRET).encode()).digest()
    return Fernet(base64.urlsafe_b64encode(key))


def encrypt(value: str) -> str:
    return _fernet().encrypt(value.encode()).decode()


def decrypt(token: str) -> str:
    return _fernet().decrypt(token.encode()).decode()
