from crewai import Crew, Task
from soc_agents.triage_agent import triage_agent
from soc_agents.hunter_agent import hunter_agent
from soc_agents.forensics_agent import forensics_agent
from soc_agents.reporter_agent import reporter_agent

def run_soc_pipeline(alert: str) -> str:
    t1 = Task(
        description=f"Triage this alert and assign a severity score:\n{alert}",
        agent=triage_agent,
        expected_output="Severity score (1-10) and brief classification summary."
    )
    t2 = Task(
        description="Based on the triage findings, hunt for related log events and enrich any IOCs found.",
        agent=hunter_agent,
        expected_output="Related events found, IOC enrichment results, suspected MITRE tactic."
    )
    t3 = Task(
        description="Using all findings so far, reconstruct the attack timeline and check for lateral movement.",
        agent=forensics_agent,
        expected_output="Ordered timeline of events, lateral movement assessment."
    )
    t4 = Task(
        description="Write a full incident report summarizing all findings from Triage, Hunter, and Forensics.",
        agent=reporter_agent,
        expected_output="Structured incident report: Summary, Severity, Timeline, Recommended Actions."
    )

    crew = Crew(
        agents=[triage_agent, hunter_agent, forensics_agent, reporter_agent],
        tasks=[t1, t2, t3, t4],
        verbose=True
    )
    return crew.kickoff()

if __name__ == "__main__":
    sample_alert = "Suspicious SMB traffic detected from 192.168.1.105 to multiple hosts on port 445."
    print("\n=== SOC PIPELINE RESULT ===\n")
    print(run_soc_pipeline(sample_alert))