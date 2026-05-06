import re
from crewai import Crew, Task
from soc_agents.reporter_agent import reporter_agent
from tools.agent_tools import (
    assign_severity,
    query_vector_db,
    mitre_lookup,
    enrich_ioc,
    timeline_reconstruct,
    lateral_movement_check,
)
from hitl.queue_manager import enqueue_alert


def extract_ip(text: str) -> str:
    match = re.search(r'\b(\d{1,3}(?:\.\d{1,3}){3})\b', text)
    return match.group(1) if match else "unknown"


def extract_severity_score(severity_result: str) -> int:
    try:
        return int(severity_result.split("Severity: ")[1].split("/")[0].strip())
    except (IndexError, ValueError):
        return 5


def extract_attack_type(severity_result: str) -> str:
    try:
        return severity_result.split("Attack Type: ")[1].split("\n")[0].strip()
    except IndexError:
        return "unknown"


def run_soc_pipeline(alert: str) -> str:
    attacker_ip = extract_ip(alert)

    # ── Phase 1: Triage (pure Python) ────────────────────────────────────
    severity_result = assign_severity.run(alert)
    severity_score  = extract_severity_score(severity_result)
    attack_type     = extract_attack_type(severity_result)

    triage_output = (
        f"Alert: {alert}\n"
        f"Attack Type: {attack_type}\n"
        f"Severity: {severity_score}/10\n"
        f"Reasoning: {severity_result}"
    )

    # ── Phase 2: Threat Hunting (pure Python) ────────────────────────────
    log_results  = query_vector_db.run(f"{attack_type} high severity")
    mitre_result = mitre_lookup.run("T1021")
    ioc_result   = enrich_ioc.run(attacker_ip)

    hunter_output = (
        f"Related log events:\n{log_results}\n\n"
        f"MITRE ATT&CK:\n{mitre_result}\n\n"
        f"IOC Enrichment ({attacker_ip}):\n{ioc_result}"
    )

    # ── Phase 3: Forensics (pure Python) ─────────────────────────────────
    timeline_result = timeline_reconstruct.run(attacker_ip)
    lateral_result  = lateral_movement_check.run(attacker_ip)

    forensics_output = (
        f"Attack Timeline:\n{timeline_result}\n\n"
        f"Lateral Movement Check:\n{lateral_result}"
    )

    # ── Phase 4: Report (ReporterAgent via CrewAI) ────────────────────────
    report_task = Task(
        description=(
            f"Write a complete incident report using ONLY the findings below.\n\n"
            f"=== TRIAGE ===\n{triage_output}\n\n"
            f"=== THREAT HUNTING ===\n{hunter_output}\n\n"
            f"=== FORENSICS ===\n{forensics_output}\n\n"
            f"Rules:\n"
            f"- Use the exact MITRE technique from the Threat Hunting section\n"
            f"- Use the exact timestamps from the Forensics timeline\n"
            f"- Do NOT call any tools\n"
            f"- Do NOT invent any data not present above"
        ),
        agent=reporter_agent,
        expected_output=(
            "Markdown incident report with these sections:\n"
            "## Summary\n"
            "## Severity\n"
            "## Attack Timeline\n"
            "## MITRE Technique\n"
            "## Recommended Actions\n"
            "## Incident Status"
        )
    )

    report_crew = Crew(agents=[reporter_agent], tasks=[report_task], verbose=True)
    report = str(report_crew.kickoff())

    # ── HITL Gate: queue high-severity alerts for human approval ──────────
    if severity_score >= 8:
        enqueue_alert(
            alert_text=alert,
            source_ip=attacker_ip,
            attack_type=attack_type,
            severity=severity_score,
            report=report
        )
        print(
            f"\n⚠️  HIGH SEVERITY ({severity_score}/10) — "
            f"Alert queued for human approval in dashboard."
        )
    else:
        print(f"\nℹ️  Severity {severity_score}/10 — below threshold, no approval needed.")

    return report


if __name__ == "__main__":
    sample_alert = "Suspicious SMB traffic detected from 192.168.1.105 to multiple hosts on port 445."
    print("\n=== SOC PIPELINE RESULT ===\n")
    result = run_soc_pipeline(sample_alert)
    print("\n=== FINAL REPORT ===\n")
    print(result)