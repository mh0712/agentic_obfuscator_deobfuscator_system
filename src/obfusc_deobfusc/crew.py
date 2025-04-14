from crewai import Agent, Task, Crew
from tools.custom_tool import DetectFormatTool, ObfuscateTool, DeobfuscateTool
import yaml, os

def load_yaml(path):
    with open(os.path.join(os.path.dirname(__file__), path), "r") as f:
        return yaml.safe_load(f)

agents_config = load_yaml("config/agents.yaml")
tasks_config = load_yaml("config/tasks.yaml")

# Tools
format_tool = DetectFormatTool()
obfuscate_tool = ObfuscateTool()
deobfuscate_tool = DeobfuscateTool()

# Agents with tools
agents = {}

for name, config in agents_config.items():
    tools = []
    if "parser" in name:
        tools = [format_tool]
    elif "obfuscation" in name:
        tools = [obfuscate_tool]
    elif "deobfuscation" in name:
        tools = [deobfuscate_tool]

    agent = Agent(
        role=config["role"],
        goal=config["goal"],
        backstory=config["backstory"],
        tools=tools,
        verbose=True
    )
    agents[name] = agent

# Tasks
tasks = [
    Task(description=tasks_config["detect_format"]["description"],
         expected_output=tasks_config["detect_format"]["expected_output"],
         agent=agents["input_parser_agent"]),
    Task(description=tasks_config["web_search"]["description"],
         expected_output=tasks_config["web_search"]["expected_output"],
         agent=agents["researcher_agent"]),
    Task(description=tasks_config["execute_code"]["description"],
         expected_output=tasks_config["execute_code"]["expected_output"],
         agent=agents["obfuscation_agent"]),
    Task(description=tasks_config["obfuscate_code"]["description"],
         expected_output=tasks_config["obfuscate_code"]["expected_output"],
         agent=agents["obfuscation_agent"]),
    Task(description=tasks_config["deobfuscate_code"]["description"],
         expected_output=tasks_config["deobfuscate_code"]["expected_output"],
         agent=agents["deobfuscation_agent"]),
    Task(description=tasks_config["verify_correctness"]["description"],
         expected_output=tasks_config["verify_correctness"]["expected_output"],
         agent=agents["verifier_agent"]),
]

obfuscation_crew = Crew(
    agents=list(agents.values()),
    tasks=tasks,
    verbose=True,
    memory=True
)

__all__ = ["agents", "obfuscation_crew"]
