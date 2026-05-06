import joblib, json, os
import numpy as np
from crewai.tools import tool
from memory.chroma_store import query_logs

rf_model = joblib.load("rf_multiclass.pkl")

ATTACK_KEYWORDS = {
    "lateral_movement": ["smb", "port 445", "rdp", "wmi", "psexec", "pass-the-hash"],
    "dos":              ["ddos", "dos", "flood", "syn flood", "udp flood"],
    "probe":            ["port scan", "nmap", "reconnaissance", "sweep"],
    "r2l":              ["brute force", "failed login", "credential", "ssh attempt"],
    "u2r":              ["privilege escalation", "rootkit", "sudo", "kernel exploit"],
}

SEVERITY_MAP = {
    "lateral_movement": 9,
    "u2r":              9,
    "r2l":              6,
    "dos":              7,
    "probe":            5,
    "normal":           1,
}

def _keyword_classify(text: str) -> str:
    t = text.lower()
    for attack_type, keywords in ATTACK_KEYWORDS.items():
        if any(k in t for k in keywords):
            return attack_type
    return "unknown"

@tool("query_vector_db")
def query_vector_db(query: str) -> str:
    """Search the SOC log vector store for events semantically matching the query."""
    results = query_logs(query)
    return "\n".join(results) if results else "No matching logs found."

@tool("assign_severity")
def assign_severity(alert_description: str) -> str:
    """
    Classify an alert and assign a severity score 1-10.
    Input: plain text description of the alert or suspicious activity.
    """
    attack_type = _keyword_classify(alert_description)
    severity = SEVERITY_MAP.get(attack_type, 5)
    return (
        f"Attack Type: {attack_type}\n"
        f"Severity: {severity}/10\n"
        f"Reasoning: Keyword match on alert text → '{attack_type}' pattern detected."
    )

@tool("enrich_ioc")
def enrich_ioc(ip: str) -> str:
    """
    Enrich an IP address using AbuseIPDB.
    Input: a valid IPv4 address string, e.g. '192.168.1.105'.
    """
    api_key = os.getenv("ABUSEIPDB_KEY", "")
    if not api_key:
        return f"AbuseIPDB key not set. Manual enrichment needed for {ip}."
    import requests
    r = requests.get(
        "https://api.abuseipdb.com/api/v2/check",
        headers={"Key": api_key, "Accept": "application/json"},
        params={"ipAddress": ip, "maxAgeInDays": 90}
    )
    d = r.json().get("data", {})
    return (
        f"IP: {ip}\n"
        f"Abuse Score: {d.get('abuseConfidenceScore')}%\n"
        f"Total Reports: {d.get('totalReports')}\n"
        f"Country: {d.get('countryCode')}"
    )
import json as _json
from collections import Counter

# ── Load MITRE ATT&CK once at startup ──────────────────────────────────────
_MITRE_DB = {}
try:
    with open("mitre_attack.json", "r", encoding="utf-8") as _f:
        _raw = _json.load(_f)
    for _obj in _raw.get("objects", []):
        if _obj.get("type") == "attack-pattern":
            for _ref in _obj.get("external_references", []):
                if _ref.get("source_name") == "mitre-attack":
                    _tid = _ref.get("external_id", "")
                    _MITRE_DB[_tid] = {
                        "name":        _obj.get("name", "Unknown"),
                        "description": _obj.get("description", "")[:300],
                        "tactic":      [p["phase_name"] for p in _obj.get("kill_chain_phases", [])],
                    }
except FileNotFoundError:
    pass  # mitre_attack.json not downloaded yet


@tool("mitre_lookup")
def mitre_lookup(technique_id: str) -> str:
    """
    Look up a MITRE ATT&CK technique by ID (e.g. 'T1021') or tactic name (e.g. 'lateral_movement').
    Returns the technique name, description, and kill chain phase.
    """
    # Try direct ID match first
    technique_id = technique_id.strip().upper()
    if technique_id in _MITRE_DB:
        t = _MITRE_DB[technique_id]
        return (
            f"Technique: {technique_id} — {t['name']}\n"
            f"Tactics: {', '.join(t['tactic'])}\n"
            f"Description: {t['description']}"
        )
    # Fallback: search by tactic/keyword in name
    query = technique_id.lower().replace("_", " ")
    matches = [
        f"{tid}: {t['name']} ({', '.join(t['tactic'])})"
        for tid, t in _MITRE_DB.items()
        if query in t["name"].lower() or any(query in tac for tac in t["tactic"])
    ]
    if matches:
        return "Matching techniques:\n" + "\n".join(matches[:5])
    return f"No MITRE technique found for '{technique_id}'."


@tool("timeline_reconstruct")
def timeline_reconstruct(ip: str) -> str:
    """
    Reconstruct the attack timeline for a given IP address.
    Queries ChromaDB for all events involving this IP, sorted by timestamp.
    Input: IPv4 address string e.g. '10.0.1.5'
    """
    from memory.chroma_store import get_log_collection
    col = get_log_collection()
    results = col.query(
        query_texts=[f"IP address {ip}"],
        n_results=20,
        where={"source_ip": ip} if ip != "unknown" else None
    )
    docs = results["documents"][0] if results["documents"] else []
    metas = results["metadatas"][0] if results["metadatas"] else []

    if not docs:
        # Fallback: semantic search without metadata filter
        results = col.query(query_texts=[ip], n_results=10)
        docs = results["documents"][0] if results["documents"] else []
        metas = results["metadatas"][0] if results["metadatas"] else []

    if not docs:
        return f"No timeline events found for IP {ip}."

    # Sort by timestamp
    events = sorted(zip(metas, docs), key=lambda x: x[0].get("timestamp", ""))
    timeline = []
    for meta, doc in events:
        ts = meta.get("timestamp", "unknown time")
        short = doc[:120].replace("\n", " ")
        timeline.append(f"[{ts}] {short}")

    return f"Timeline for {ip} ({len(timeline)} events):\n" + "\n".join(timeline)


@tool("lateral_movement_check")
def lateral_movement_check(ip: str) -> str:
    """
    Check if a source IP has communicated with multiple destination hosts (lateral movement indicator).
    Input: source IPv4 address e.g. '10.0.1.5'
    """
    from memory.chroma_store import get_log_collection
    col = get_log_collection()
    results = col.query(
        query_texts=[f"lateral movement from {ip}"],
        n_results=30
    )
    metas = results["metadatas"][0] if results["metadatas"] else []

    dest_ips = [
        m["dest_ip"] for m in metas
        if m.get("source_ip") == ip and m.get("dest_ip") not in ("unknown", "")
    ]

    if not dest_ips:
        return f"No lateral movement evidence found for {ip}."

    unique_dests = list(set(dest_ips))
    counts = Counter(dest_ips)

    if len(unique_dests) >= 3:
        verdict = "⚠️ HIGH CONFIDENCE lateral movement detected"
    elif len(unique_dests) >= 2:
        verdict = "⚠️ POSSIBLE lateral movement"
    else:
        verdict = "ℹ️ Single destination — not conclusive"

    return (
        f"{verdict}\n"
        f"Source IP: {ip}\n"
        f"Unique destinations: {len(unique_dests)}\n"
        f"Destination IPs: {', '.join(unique_dests)}\n"
        f"Connection counts: {dict(counts)}"
    )