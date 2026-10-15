import os

os.environ["CODSHIELD_DISPUTE_RATE"] = "1000"
os.environ["CODSHIELD_LOGIN_RATE"] = "1000"       # every test shares one client address
os.environ["CODSHIELD_NOTIFY_TEST"] = "1"      # codshield.notify records texts and emails instead of sending them


def last_message(channel: str, to_contains: str = "") -> dict:
    from codshield import notify
    return next(m for m in reversed(notify.SENT) if m["channel"] == channel and to_contains in m["to"])


def verified_dispute(client, phone: str, reason: str, country: str = "PK"):
    """Request a code, read it from the recorded SMS, and open the dispute with it."""
    import re
    v = client.post("/v1/disputes/verify", json={"phone": phone, "country": country})
    assert v.status_code == 200, v.text
    code = re.search(r"\b(\d{6})\b", last_message("sms")["text"]).group(1)
    return client.post("/v1/disputes", json={"phone": phone, "country": country, "reason": reason,
                                            "verification_id": v.json()["verification_id"], "code": code})
