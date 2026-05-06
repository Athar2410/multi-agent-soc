from crewai import Crew, Task
from soc_agents.triage_agent import triage_agent
from soc_agents.reporter_agent import reporter_agent
from tools.agent_tools import (
    assign_severity, query_vector_db, mitre_lookup,
    enrich_ioc, timeline_reconstruct, lateral_movement_check
)
import re

def extract_ip(text: str) -> str:
    match = re.search(r'\b(\d{1,3}(?:\.\d{1,3}){3})\b', text)
    return match.group(1) if match else "unknown"

def run_soc_pipeline(alert: str) -> str:
    attacker_ip = extract_ip(alert)

    # ── All tool calls directly in Python ────────────────────────────────
    severity_result  = assign_severity.run(alert)
    log_results      = query_vector_db.run("lateral movement SMB attack high severity")
    mitre_result     = mitre_lookup.run("T1021")
    ioc_result       = enrich_ioc.run(attacker_ip)
    timeline_result  = timeline_reconstruct.run(attacker_ip)
    lateral_result   = lateral_movement_check.run(attacker_ip)

    triage_output = (
        f"Alert: {alert}\n"
        f"Attack Type: {severity_result}"
    )
    hunter_output = (
        f"Related log events:\n{log_results}\n\n"
        f"MITRE ATT&CK:\n{mitre_result}\n\n"
        f"IOC Enrichment ({attacker_ip}):\n{ioc_result}"
    )
    forensics_output = (
        f"Attack Timeline:\n{timeline_result}\n\n"
        f"Lateral Movement Check:\n{lateral_result}"
    )

    # ── Only ReporterAgent uses CrewAI ────────────────────────────────────
    report_task = Task(
        description=(
            f"Write a complete incident report using ONLY the findings below.\n\n"
            f"=== TRIAGE ===\n{triage_output}\n\n"
            f"=== THREAT HUNTING ===\n{hunter_output}\n\n"
            f"=== FORENSICS ===\n{forensics_output}\n\n"
            f"Use the exact MITRE technique from Threat Hunting. "
            f"Use the exact timestamps from Forensics. "
            f"Do NOT invent any data not present above."
        ),
        agent=reporter_agent,
        expected_output="Markdown incident report: Summary, Severity, Timeline, MITRE Technique, Recommended Actions."
    )
    report_crew = Crew(agents=[reporter_agent], tasks=[report_task], verbose=True)
    return str(report_crew.kickoff())

    
if __name__ == "__main__":
    sample_alert = "Suspicious SMB traffic detected from 192.168.1.105 to multiple hosts on port 445."
    print("\n=== SOC PIPELINE RESULT ===\n")
    print(run_soc_pipeline(sample_alert))