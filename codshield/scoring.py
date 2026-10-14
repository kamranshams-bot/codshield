"""Risk scoring.

Principles
- Facts, not labels: score is built from reported delivery events.
- Time decay: an event loses half its weight every HALF_LIFE_DAYS.
- Corroboration: one merchant alone cannot push a customer to HIGH.
- Good history counts: paid deliveries pull the score down.
- Disputed / removed events are ignored.
"""
import math
from collections import defaultdict
from datetime import datetime

from .config import settings
from .models import Event, EventStatus, EventType, utcnow

WEIGHTS = {
    EventType.REFUSED_AT_DOOR.value: 3.0,
    EventType.FAKE_ORDER.value: 4.0,
    EventType.FAKE_ADDRESS.value: 3.5,
    EventType.RETURN_ABUSE.value: 3.0,
    EventType.CHARGEBACK.value: 3.5,
    EventType.UNREACHABLE.value: 1.0,     # often courier-side, weak signal
    EventType.DELIVERED_PAID.value: -1.5,
}

# identifier strength: an address match is weaker than a phone match
KIND_FACTOR = {"phone": 1.0, "email": 0.9, "address": 0.5}

SCALE = 8.0  # raw points at which score reaches ~63/100


def _decay(occurred: datetime, now: datetime) -> float:
    age_days = max((now - occurred).total_seconds() / 86400, 0)
    return 0.5 ** (age_days / settings.HALF_LIFE_DAYS)


def score_events(events_with_kind: list[tuple[Event, str, float]], now: datetime | None = None) -> dict:
    """events_with_kind: [(event, matched_kind, merchant_trust_weight)]"""
    now = now or utcnow()
    best: dict[int, tuple[Event, float, float]] = {}
    for ev, kind, trust in events_with_kind:
        if ev.status != EventStatus.ACTIVE.value:
            continue
        f = KIND_FACTOR.get(kind, 0.5)
        if ev.id not in best or f > best[ev.id][1]:
            best[ev.id] = (ev, f, trust)

    raw = 0.0
    by_type = defaultdict(int)
    neg_merchants, paid = set(), 0
    last_negative = None
    for ev, f, trust in best.values():
        w = WEIGHTS.get(ev.type, 0.0)
        raw += w * f * trust * _decay(ev.occurred_at, now)
        if w > 0:
            by_type[ev.type] += 1
            neg_merchants.add(ev.merchant_id)
            last_negative = max(last_negative or ev.occurred_at, ev.occurred_at)
        elif ev.type == EventType.DELIVERED_PAID.value:
            paid += 1

    raw = max(raw, 0.0)
    score = round(100 * (1 - math.exp(-raw / SCALE)))
    # corroboration cap
    if len(neg_merchants) < 2:
        score = min(score, 59)

    band = "high" if score >= 60 else "medium" if score >= 30 else "low"
    action = {
        "low": "ship_normally",
        "medium": "confirm_by_call_or_otp",
        "high": "require_prepayment_or_partial_advance",
    }[band]

    reasons = [f"{n} x {t}" for t, n in sorted(by_type.items(), key=lambda x: -x[1])]
    if neg_merchants:
        reasons.append(f"reported by {len(neg_merchants)} merchant(s)")
    if paid:
        reasons.append(f"{paid} successful paid deliveries")
    if not best:
        reasons.append("no history in network")

    return {
        "score": score,
        "band": band,
        "recommended_action": action,
        "reasons": reasons,
        "negative_events": sum(by_type.values()),
        "paid_deliveries": paid,
        "reporting_merchants": len(neg_merchants),
        "last_negative_at": last_negative.isoformat() if last_negative else None,
    }
