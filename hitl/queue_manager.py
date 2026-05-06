import sqlite3
import json
from datetime import datetime

DB_PATH = "hitl_queue.db"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS alert_queue (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_text  TEXT NOT NULL,
            source_ip   TEXT,
            attack_type TEXT,
            severity    INTEGER,
            report      TEXT,
            status      TEXT DEFAULT 'pending',
            analyst     TEXT,
            decision_at TEXT,
            created_at  TEXT
        )
    """)
    conn.commit()
    conn.close()

def enqueue_alert(alert_text: str, source_ip: str, attack_type: str, severity: int, report: str):
    init_db()
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        INSERT INTO alert_queue (alert_text, source_ip, attack_type, severity, report, status, created_at)
        VALUES (?, ?, ?, ?, ?, 'pending', ?)
    """, (alert_text, source_ip, attack_type, severity, report, datetime.now().isoformat()))
    conn.commit()
    conn.close()

def get_pending_alerts() -> list[dict]:
    init_db()
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT * FROM alert_queue WHERE status = 'pending' ORDER BY severity DESC, created_at ASC")
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    return rows

def get_all_alerts() -> list[dict]:
    init_db()
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT * FROM alert_queue ORDER BY created_at DESC LIMIT 100")
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    return rows

def update_decision(alert_id: int, status: str, analyst: str):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        UPDATE alert_queue
        SET status = ?, analyst = ?, decision_at = ?
        WHERE id = ?
    """, (status, analyst, datetime.now().isoformat(), alert_id))
    conn.commit()
    conn.close()