"""
CrewAI Multi-Agent — Example companion code for AGENTSECURITY.md

Demonstrates how to apply a security policy across multiple agents
in a CrewAI setup. Each agent in the crew inherits the bounds of the
overall policy, preventing rogue tool usage.
"""

import os
from urllib.parse import urlparse

# --- Security policy integration ---
# Load from AGENTSECURITY.md using agentsec.parser in production.
POLICY_TIER = "standard"
ALLOWED_DOMAINS = ["wikipedia.org", "arxiv.org", "github.com"]
ALLOWED_OUTPUT_DIR = "./outputs/"

def validate_search_url(url: str) -> bool:
    """Enforce tools.web_search.scope from AGENTSECURITY.md."""
    domain = urlparse(url).hostname or ""
    return any(domain.endswith(d) for d in ALLOWED_DOMAINS)

def validate_file_write(path: str) -> bool:
    """Enforce tools.file_write.scope from AGENTSECURITY.md."""
    return path.startswith(ALLOWED_OUTPUT_DIR)

def main():
    """
    To run this example with a real LLM, install CrewAI:
      pip install crewai langchain-openai
    """
    
    # 1. Initialize Tools with Security Wrappers
    # class SecureSearchTool(Tool):
    #     def _run(self, query: str):
    #         # Extract URL and validate with `validate_search_url`
    #         # if not validate_search_url(url): return "Access Denied"
    #         pass
    
    # 2. Define Agents
    # from crewai import Agent, Task, Crew, Process
    # researcher = Agent(
    #     role='Senior Researcher',
    #     goal='Research topics using safe web search',
    #     backstory='Expert analyst.',
    #     tools=[secure_search_tool],
    #     allow_delegation=False
    # )
    # writer = Agent(
    #     role='Technical Writer',
    #     goal='Write reports to the output directory',
    #     backstory='Skilled writer.',
    #     tools=[secure_file_write_tool],
    #     allow_delegation=False
    # )
    
    # 3. Form the Crew and Execute
    # crew = Crew(
    #     agents=[researcher, writer],
    #     tasks=[research_task, write_task],
    #     process=Process.sequential
    # )
    # result = crew.kickoff()

    print("CrewAI Multi-Agent (skeleton)")
    print(f"Policy Tier: {POLICY_TIER}")
    print(f"Allowed Search Domains: {ALLOWED_DOMAINS}")
    print("\nTo validate: agentsec validate .")
    print("To scan:     agentsec check .")

if __name__ == "__main__":
    main()
