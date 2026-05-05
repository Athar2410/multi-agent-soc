from crewai import Agent, LLM

llm = LLM(model="ollama/llama3.1", base_url="http://localhost:11434")

reporter_agent = Agent(
    role="Incident Report Writer",
    goal="Compile all agent findings into a structured, human-readable incident report.",
    backstory="You synthesize technical findings from the SOC team into clear incident reports.",
    tools=[],
    llm=llm, verbose=True, allow_delegation=False
)
