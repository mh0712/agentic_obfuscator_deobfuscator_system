from crewai import Agent, Task, Crew, LLM
from tools.format_detector import detect_code_format
import yaml, os

def load_yaml(path):
    with open(os.path.join(os.path.dirname(__file__), path), "r") as f:
        return yaml.safe_load(f)

agents_config = load_yaml("config/agents.yaml")
tools_config = load_yaml("config/tasks.yaml")


# Initialize Groq model
llm = LLM(model="groq/llama-3.3-70b-versatile")

# Run the code-based format detection manually (not via LLM)
file_path = "C:\\Users\\celin\\Desktop\\usj\\FYP\\agentic_obfuscator_deobfuscator_system\\samples\\hello.py"
format_detection_result = detect_code_format(file_path)
print("[+] Format Detection Result:", format_detection_result)

# Create agents using loaded config
input_parser_agent = Agent(
    role=agents_config['input_parser_agent']['role'],
    goal=agents_config['input_parser_agent']['goal'],
    backstory=agents_config['input_parser_agent']['backstory'],
    llm=None,  # No LLM needed
    verbose=False
)

researcher_agent = Agent(
    role=agents_config['researcher_agent']['role'],
    goal=agents_config['researcher_agent']['goal'],
    backstory=agents_config['researcher_agent']['backstory'],
    llm=llm,
    verbose=True
)

executer_agent = Agent(
    role=agents_config['executer_agent']['role'],
    goal=agents_config['executer_agent']['goal'],
    backstory=agents_config['executer_agent']['backstory'],
    llm=llm,
    verbose=True
)

# Only proceed with the researcher and executor if code is obfuscated
if format_detection_result['obfuscated']== False and format_detection_result['language'] in ["python", "javascript"]:
    language = format_detection_result['language']

    # Modify web search task to specify language for search
    web_search_task = Task(
        description=f"{tools_config['web_search']['description']} Target language: {language}.",
        expected_output=tools_config['web_search']['expected_output'],
        agent=researcher_agent
    )

    obfuscation_execution_task = Task(
        description=tools_config['execute_code']['description'],
        expected_output=tools_config['execute_code']['expected_output'],
        agent=executer_agent,
        dependencies=[web_search_task]
    )

    # Create the crew with researcher and executer agents
    crew = Crew(
        agents=[researcher_agent, executer_agent],
        tasks=[web_search_task, obfuscation_execution_task],
        verbose=True
    )

    result = crew.kickoff()
    print(result)
else:
    print("[-] Code is not obfuscated or unsupported language.")

