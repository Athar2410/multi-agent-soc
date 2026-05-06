from crewai import Agent, LLM
from tools.agent_tools import query_vector_db, timeline_reconstruct, lateral_movement_check

llm = LLM(model="ollama/llama3.1", base_url="http://localhost:11434")

forensics_agent = Agent(
    role="Digital Forensics Investigator",
    goal="Reconstruct the attack timeline and confirm lateral movement using forensic tools.",
    backstory=(
        "You are a digital forensics expert. Always call timeline_reconstruct with the attacker IP "
        "to get a real event timeline. Then call lateral_movement_check to confirm if the attacker "
        "spread to multiple hosts. Base your findings only on tool results, not assumptions."
    ),
    tools=[query_vector_db, timeline_reconstruct, lateral_movement_check],
    llm=llm, verbose=True, allow_delegation=False, max_iter=5
)