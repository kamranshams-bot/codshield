"""Aggregate reports. Counts only; no customer identifiers ever leave this module."""
from datetime import timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .models import (CheckLog, Dispute, Event, EventStatus, EventType, Identity,
                     Merchant, utcnow)

NEGATIVE = [t.value for t in EventType if t != EventType.DELIVERED_PAID]


def _daily(rows, days, start):
    """rows: [(date, key, n)] -> {"dates": [...], "series": {key: [n per day]}}"""
    dates = [(start + timedelta(days=i)).date().isoformat() for i in range(days + 1)]
    idx = {d: i for i, d in enumerate(dates)}
    series: dict[str, list[int]] = {}
    for d, key, n in rows:
        d = d.isoformat() if hasattr(d, "isoformat") else str(d)[:10]
        if d in idx:
            series.setdefault(key, [0] * len(dates))[idx[d]] += n
    return {"dates": dates, "series": series}


def build_report(s: Session, days: int = 30, merchant_id: int | None = None,
                 countries: set | None = None) -> dict:
    days = max(1, min(int(days), 365))
    now = utcnow()
    start = (now - timedelta(days=days)).replace(hour=0, minute=0, second=0, microsecond=0)

    ev_where = [Event.occurred_at >= start, Event.status != EventStatus.REMOVED.value]
    ck_where = [CheckLog.created_at >= start]
    if merchant_id is not None:
        ev_where.append(Event.merchant_id == merchant_id)
        ck_where.append(CheckLog.merchant_id == merchant_id)
    if countries:
        ev_where.append(Event.country.in_(sorted(countries)))
        ck_where.append(CheckLog.country.in_(sorted(countries)))

    ev_day = func.date(Event.occurred_at)
    ev_rows = s.execute(select(ev_day, Event.type, func.count()).where(*ev_where)
                        .group_by(ev_day, Event.type)).all()
    by_type = {}
    for _, t, n in ev_rows:
        by_type[t] = by_type.get(t, 0) + n
    by_country = dict(s.execute(select(Event.country, func.count()).where(*ev_where)
                                .group_by(Event.country)).all())

    ck_day = func.date(CheckLog.created_at)
    ck_rows = s.execute(select(ck_day, CheckLog.band, func.count()).where(*ck_where)
                        .group_by(ck_day, CheckLog.band)).all()
    by_band = {"low": 0, "medium": 0, "high": 0}
    for _, b, n in ck_rows:
        by_band[b] = by_band.get(b, 0) + n
    checks = sum(by_band.values())

    negatives = sum(n for t, n in by_type.items() if t in NEGATIVE)
    refused_value = s.execute(
        select(Event.currency, func.sum(Event.amount)).where(
            *ev_where, Event.type.in_(NEGATIVE), Event.amount.is_not(None))
        .group_by(Event.currency)).all()

    report = {
        "days": days,
        "from": start.date().isoformat(),
        "to": now.date().isoformat(),
        "scope": "merchant" if merchant_id is not None else "network",
        "totals": {
            "checks": checks,
            "flagged": by_band["medium"] + by_band["high"],
            "high_risk": by_band["high"],
            "outcomes_reported": sum(by_type.values()),
            "negative_outcomes": negatives,
            "paid_deliveries": by_type.get(EventType.DELIVERED_PAID.value, 0),
        },
        "negative_value": {c or "?": round(v or 0, 2) for c, v in refused_value},
        "by_type": by_type,
        "by_country": by_country,
        "checks_by_band": by_band,
        "outcomes_daily": _daily(ev_rows, days, start),
        "checks_daily": _daily(ck_rows, days, start),
        "network": {
            "merchants": s.scalar(select(func.count(Merchant.id)).where(Merchant.active.is_(True))),
            "customers_on_file": s.scalar(select(func.count(Identity.id))),
        },
    }

    if merchant_id is None:  # admin-only extras
        top = s.execute(
            select(Merchant.id, Merchant.name, Merchant.country, Merchant.trust_weight, func.count(Event.id))
            .join(Event, Event.merchant_id == Merchant.id)
            .where(Event.occurred_at >= start)
            .group_by(Merchant.id, Merchant.name, Merchant.country, Merchant.trust_weight)
            .order_by(func.count(Event.id).desc()).limit(10)).all()
        report["top_contributors"] = [
            {"id": i, "name": n, "country": c, "trust_weight": w, "reports": r} for i, n, c, w, r in top]
        report["disputes"] = {
            "opened": s.scalar(select(func.count(Dispute.id)).where(Dispute.created_at >= start)),
            "open_now": s.scalar(select(func.count(Dispute.id)).where(Dispute.status == "open")),
            "upheld": s.scalar(select(func.count(Dispute.id)).where(
                Dispute.status == "upheld", Dispute.resolved_at >= start)),
            "rejected": s.scalar(select(func.count(Dispute.id)).where(
                Dispute.status == "rejected", Dispute.resolved_at >= start)),
        }
    return report
