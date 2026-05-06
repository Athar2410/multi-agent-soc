import sqlite3
from datetime import datetime, timedelta
from collections import Counter
from hitl.queue_manager import DB_PATH, init_db

def get_all_alerts_raw() -> list[dict]:
    init_db()
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT * FROM alert_queue ORDER BY created_at ASC")
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    return rows

def compute_kpis() -> dict:
    alerts = get_all_alerts_raw()
    total     = len(alerts)
    pending   = sum(1 for a in alerts if a["status"] == "pending")
    approved  = sum(1 for a in alerts if a["status"] == "approved")
    rejected  = sum(1 for a in alerts if a["status"] == "rejected")
    escalated = sum(1 for a in alerts if a["status"] == "escalated")

    decided = approved + rejected + escalated
    fp_rate  = round((rejected / decided * 100), 1) if decided > 0 else 0
    apr_rate = round((approved / decided * 100), 1) if decided > 0 else 0

    # Mean time to respond (minutes)
    mttr_list = []
    for a in alerts:
        if a["created_at"] and a["decision_at"]:
            try:
                t1 = datetime.fromisoformat(a["created_at"])
                t2 = datetime.fromisoformat(a["decision_at"])
                mttr_list.append((t2 - t1).total_seconds() / 60)
            except Exception:
                pass
    mttr = round(sum(mttr_list) / len(mttr_list), 1) if mttr_list else None

    return {
        "total":     total,
        "pending":   pending,
        "approved":  approved,
        "rejected":  rejected,
        "escalated": escalated,
        "fp_rate":   fp_rate,
        "apr_rate":  apr_rate,
        "mttr":      mttr,
    }

def get_attack_type_distribution() -> dict:
    alerts = get_all_alerts_raw()
    types = [a["attack_type"] or "unknown" for a in alerts]
    return dict(Counter(types))

def get_severity_distribution() -> dict:
    alerts = get_all_alerts_raw()
    buckets = {"Critical (9-10)": 0, "High (7-8)": 0, "Medium (5-6)": 0, "Low (<5)": 0}
    for a in alerts:
        s = a["severity"] or 0
        if s >= 9:
            buckets["Critical (9-10)"] += 1
        elif s >= 7:
            buckets["High (7-8)"] += 1
        elif s >= 5:
            buckets["Medium (5-6)"] += 1
        else:
            buckets["Low (<5)"] += 1
    return buckets

def get_hourly_volume() -> dict:
    alerts = get_all_alerts_raw()
    hourly = Counter()
    for a in alerts:
        if a["created_at"]:
            try:
                dt = datetime.fromisoformat(a["created_at"])
                hour = dt.strftime("%Y-%m-%d %H:00")
                hourly[hour] += 1
            except Exception:
                pass
    return dict(sorted(hourly.items()))

def get_analyst_leaderboard() -> dict:
    alerts = get_all_alerts_raw()
    analysts = [a["analyst"] for a in alerts if a["analyst"]]
    return dict(Counter(analysts))