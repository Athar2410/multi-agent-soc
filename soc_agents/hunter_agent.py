from crewai import Agent, LLM
from tools.agent_tools import query_vector_db, enrich_ioc, mitre_lookup

llm = LLM(model="ollama/llama3.1", base_url="http://localhost:11434")

hunter_agent = Agent(
    role="Threat Hunter",
    goal="Search logs semantically, enrich IOCs, and map findings to MITRE ATT&CK techniques.",
    backstory=(
        "You are an expert threat hunter. Given a triage report, you search the log database "
        "for related events, enrich suspicious IPs, and always call mitre_lookup to get the "
        "real ATT&CK technique details for any tactic or technique ID you find."
    ),
    tools=[query_vector_db, enrich_ioc, mitre_lookup],
    llm=llm,
    verbose=True,
    allow_delegation=False,
    max_iter=5
)