import os
from datetime import datetime

BLOCK_LOG = "blocked_ips.log"

def block_ip(ip: str, reason: str, analyst: str) -> str:
    """Simulates blocking an IP — logs to file (replace with real firewall API call)."""
    entry = f"[{datetime.now().isoformat()}] BLOCKED {ip} | Reason: {reason} | Analyst: {analyst}\n"
    with open(BLOCK_LOG, "a") as f:
        f.write(entry)
    return f"✅ IP {ip} has been blocked and logged to {BLOCK_LOG}"

def create_ticket(alert_id: int, source_ip: str, attack_type: str, severity: int, analyst: str) -> str:
    """Simulates creating an incident ticket — logs to file (replace with Jira/ServiceNow API)."""
    TICKET_LOG = "tickets.log"
    ticket_id = f"INC-{alert_id:04d}"
    entry = (
        f"[{datetime.now().isoformat()}] TICKET {ticket_id} | "
        f"IP: {source_ip} | Type: {attack_type} | Severity: {severity}/10 | "
        f"Assigned to: {analyst}\n"
    )
    with open(TICKET_LOG, "a") as f:
        f.write(entry)
    return f"🎫 Ticket {ticket_id} created and assigned to {analyst}"

def run_auto_response(alert_id: int, source_ip: str, attack_type: str, severity: int, analyst: str) -> str:
    """Full auto-response chain on analyst approval."""
    results = []
    results.append(block_ip(source_ip, f"{attack_type} detected (severity {severity}/10)", analyst))
    results.append(create_ticket(alert_id, source_ip, attack_type, severity, analyst))
    return "\n".join(results)