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