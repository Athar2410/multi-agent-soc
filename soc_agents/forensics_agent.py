from crewai import Agent, LLM
from tools.agent_tools import query_vector_db

llm = LLM(model="ollama/llama3.1", base_url="http://localhost:11434")

forensics_agent = Agent(
    role="Digital Forensics Investigator",
    goal="Reconstruct attack timelines and identify lateral movement across hosts.",
    backstory="You are a forensic expert who pieces together attack sequences from raw logs.",
    tools=[query_vector_db],
    llm=llm, verbose=True, allow_delegation=False
)
