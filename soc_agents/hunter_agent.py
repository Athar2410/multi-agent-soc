# agents/hunter_agent.py
from crewai import Agent, LLM
from tools.agent_tools import query_vector_db, enrich_ioc

llm = LLM(model="ollama/llama3.1", base_url="http://localhost:11434")

hunter_agent = Agent(
    role="Threat Hunter",
    goal="Perform deep semantic log searches, enrich IOCs, and map findings to MITRE ATT&CK.",
    backstory="You hunt for hidden threats in log data using semantic search and threat intelligence.",
    tools=[query_vector_db, enrich_ioc],
    llm=llm, verbose=True, allow_delegation=False
)
