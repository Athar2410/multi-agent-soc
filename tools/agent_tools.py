import os
import re
import json
import requests
from collections import Counter
from datetime import datetime
from dotenv import load_dotenv
from crewai.tools import tool

load_dotenv()

ABUSEIPDB_KEY  = os.getenv("ABUSEIPDB_API_KEY", "")
VIRUSTOTAL_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")

# ── Load MITRE ATT&CK database once at startup ────────────────────────────────
_MITRE_DB = {}
try:
    with open("mitre_attack.json", "r", encoding="utf-8") as _f:
        _raw = json.load(_f)
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


# ── Tool 1: Assign Severity ───────────────────────────────────────────────────
@tool("assign_severity")
def assign_severity(alert_description: str) -> str:
    """
    Assign a severity score (1-10) and attack type to an alert based on keyword analysis.
    Input: plain text alert description.
    """
    alert_lower = alert_description.lower()

    severity_map = {
        "lateral_movement": 9,
        "ransomware":       10,
        "data_exfiltration":9,
        "c2_beacon":        8,
        "ssh_bruteforce":   7,
        "port_scan":        5,
        "u2r":              9,
        "r2l":              6,
        "dos":              8,
        "probe":            4,
    }

    keyword_map = {
        "lateral":    "lateral_movement",
        "smb":        "lateral_movement",
        "ransomware": "ransomware",
        "exfil":      "data_exfiltration",
        "c2":         "c2_beacon",
        "beacon":     "c2_beacon",
        "brute":      "ssh_bruteforce",
        "scan":       "port_scan",
        "u2r":        "u2r",
        "r2l":        "r2l",
        "dos":        "dos",
        "probe":      "probe",
    }

    detected_type = "unknown"
    for keyword, attack_type in keyword_map.items():
        if keyword in alert_lower:
            detected_type = attack_type
            break

    severity = severity_map.get(detected_type, 5)

    return (
        f"Attack Type: {detected_type}\n"
        f"Severity: {severity}/10\n"
        f"Reasoning: Keyword match on alert text → '{detected_type}' pattern detected."
    )


# ── Tool 2: Query Vector DB ───────────────────────────────────────────────────
@tool("query_vector_db")
def query_vector_db(query: str) -> str:
    """
    Semantically search the ChromaDB log store for events related to the query.
    Input: plain text search query e.g. 'lateral movement SMB high severity'.
    Returns up to 5 most relevant log entries.
    """
    from memory.chroma_store import get_log_collection
    col = get_log_collection()
    results = col.query(query_texts=[query], n_results=5)
    docs = results["documents"][0] if results["documents"] else []
    if not docs:
        return "No relevant logs found."
    return "\n".join(docs)


# ── Tool 3: Enrich IOC ────────────────────────────────────────────────────────
@tool("enrich_ioc")
def enrich_ioc(ip: str) -> str:
    """
    Enrich an IP address using AbuseIPDB and VirusTotal threat intel APIs.
    Returns abuse confidence score, country, ISP, and malicious vote count.
    Input: IPv4 address string e.g. '185.220.101.45'
    """
    # Skip private/internal IPs
    private_prefixes = (
        "10.", "192.168.", "172.16.", "172.17.", "172.18.",
        "172.19.", "172.2", "127.", "0."
    )
    if any(ip.startswith(p) for p in private_prefixes):
        return (
            f"ℹ️ {ip} is a private/internal IP address.\n"
            f"Threat intel APIs not applicable — investigate internal host directly."
        )

    results = []

    # ── AbuseIPDB ─────────────────────────────────────────────────────────
    if ABUSEIPDB_KEY:
        try:
            resp = requests.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": 90},
                timeout=10
            )
            if resp.status_code == 200:
                d = resp.json().get("data", {})
                results.append(
                    f"🔍 AbuseIPDB:\n"
                    f"  Abuse Confidence: {d.get('abuseConfidenceScore', 0)}%\n"
                    f"  Country: {d.get('countryCode', 'Unknown')}\n"
                    f"  ISP: {d.get('isp', 'Unknown')}\n"
                    f"  Total Reports: {d.get('totalReports', 0)}\n"
                    f"  Last Reported: {d.get('lastReportedAt', 'Never')}\n"
                    f"  Whitelisted: {d.get('isWhitelisted', False)}"
                )
            else:
                results.append(f"AbuseIPDB error: HTTP {resp.status_code}")
        except Exception as e:
            results.append(f"AbuseIPDB error: {e}")
    else:
        results.append("⚠️ AbuseIPDB key not set. Set ABUSEIPDB_API_KEY in .env")

    # ── VirusTotal ────────────────────────────────────────────────────────
    if VIRUSTOTAL_KEY:
        try:
            resp = requests.get(
                f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                headers={"x-apikey": VIRUSTOTAL_KEY},
                timeout=10
            )
            if resp.status_code == 200:
                attrs = resp.json().get("data", {}).get("attributes", {})
                stats = attrs.get("last_analysis_stats", {})
                rep   = attrs.get("reputation", 0)
                results.append(
                    f"🦠 VirusTotal:\n"
                    f"  Malicious votes:  {stats.get('malicious', 0)}\n"
                    f"  Suspicious votes: {stats.get('suspicious', 0)}\n"
                    f"  Harmless votes:   {stats.get('harmless', 0)}\n"
                    f"  Reputation score: {rep}"
                )
            elif resp.status_code == 404:
                results.append("VirusTotal: IP not found in database.")
            else:
                results.append(f"VirusTotal error: HTTP {resp.status_code}")
        except Exception as e:
            results.append(f"VirusTotal error: {e}")
    else:
        results.append("⚠️ VirusTotal key not set. Set VIRUSTOTAL_API_KEY in .env")

    return "\n\n".join(results) if results else f"No enrichment data available for {ip}."


# ── Tool 4: MITRE Lookup ──────────────────────────────────────────────────────
@tool("mitre_lookup")
def mitre_lookup(technique_id: str) -> str:
    """
    Look up a MITRE ATT&CK technique by ID (e.g. 'T1021') or keyword (e.g. 'lateral_movement').
    Returns the technique name, description, and kill chain phase.
    """
    technique_id = technique_id.strip().upper()

    if technique_id in _MITRE_DB:
        t = _MITRE_DB[technique_id]
        return (
            f"Technique: {technique_id} — {t['name']}\n"
            f"Tactics: {', '.join(t['tactic'])}\n"
            f"Description: {t['description']}"
        )

    # Fallback: keyword search
    query = technique_id.lower().replace("_", " ")
    matches = [
        f"{tid}: {t['name']} ({', '.join(t['tactic'])})"
        for tid, t in _MITRE_DB.items()
        if query in t["name"].lower() or any(query in tac for tac in t["tactic"])
    ]
    if matches:
        return "Matching techniques:\n" + "\n".join(matches[:5])

    if not _MITRE_DB:
        return "MITRE database not loaded. Run: iwr https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json -OutFile mitre_attack.json"

    return f"No MITRE technique found for '{technique_id}'."


# ── Tool 5: Timeline Reconstruct ─────────────────────────────────────────────
@tool("timeline_reconstruct")
def timeline_reconstruct(ip: str) -> str:
    """
    Reconstruct the attack timeline for a given IP address from ChromaDB logs.
    Input: IPv4 address string e.g. '10.0.1.5'
    """
    from memory.chroma_store import get_log_collection
    col = get_log_collection()

    # Try metadata filter first
    try:
        results = col.query(
            query_texts=[f"IP address {ip}"],
            n_results=20,
            where={"source_ip": ip}
        )
    except Exception:
        results = col.query(query_texts=[ip], n_results=20)

    docs  = results["documents"][0] if results["documents"] else []
    metas = results["metadatas"][0]  if results["metadatas"] else []

    # Fallback: semantic search
    if not docs:
        results = col.query(query_texts=[ip], n_results=10)
        docs  = results["documents"][0] if results["documents"] else []
        metas = results["metadatas"][0]  if results["metadatas"] else []

    if not docs:
        return f"No timeline events found for IP {ip}."

    events = sorted(zip(metas, docs), key=lambda x: x[0].get("timestamp", ""))
    timeline = []
    for meta, doc in events:
        ts    = meta.get("timestamp", "unknown time")
        short = doc[:120].replace("\n", " ")
        timeline.append(f"[{ts}] {short}")

    return f"Timeline for {ip} ({len(timeline)} events):\n" + "\n".join(timeline)


# ── Tool 6: Lateral Movement Check ───────────────────────────────────────────
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
        if m.get("source_ip") == ip and m.get("dest_ip") not in ("unknown", "", None)
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