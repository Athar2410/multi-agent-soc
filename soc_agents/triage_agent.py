from crewai import Agent, LLM
from tools.agent_tools import query_vector_db, assign_severity

llm = LLM(model="ollama/llama3.1", base_url="http://localhost:11434")

triage_agent = Agent(
    role="SOC Triage Analyst",
    goal="Classify incoming alerts and assign a severity score using the assign_severity tool.",
    backstory=(
        "You are a senior SOC triage analyst. Given an alert description, "
        "you use your tools to classify the threat and assign a severity score. "
        "Always call assign_severity with the full alert text first."
    ),
    tools=[query_vector_db, assign_severity],
    llm=llm,
    verbose=True,
    allow_delegation=False
)