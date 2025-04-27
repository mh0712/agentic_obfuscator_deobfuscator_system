
from crewai import Agent, Crew, Process, Task, LLM
from crewai.project import CrewBase, agent, crew, task
from crewai.agents.agent_builder.base_agent import BaseAgent
from typing import List
import yaml

# Function to load YAML configurations
def load_yaml_config(file_path):
    with open(file_path, 'r') as file:
        return yaml.safe_load(file)
    


@CrewBase
class ObfuscationCrew:
    """Obfuscation Crew for code obfuscation tasks"""


    
    
    def __init__(self, agents_config, tasks_config, techniques_config):
        self.agents_config = agents_config
        self.tasks_config = tasks_config
        self.techniques_config = techniques_config
        self.llm = LLM(model="groq/llama-3.3-70b-versatile")

    @agent
    def input_parser(self) -> Agent:
        return Agent(
            config=self.agents_config['input_parser'],
            verbose=True,
            llm=self.llm,
        )

    @agent
    def technique_selector(self) -> Agent:
        return Agent(
            config=self.agents_config['technique_selector'],
            verbose=True,
            llm=self.llm
        )

    @agent
    def obfuscation_llm(self) -> Agent:
        return Agent(
            config=self.agents_config['obfuscation_llm'],
            verbose=True,
            llm=self.llm,
        )

    @task
    def input_analysis_task(self) -> Task:
        return Task(
            description=self.tasks_config['input_analysis_task']['description'],
            expected_output=self.tasks_config['input_analysis_task']['expected_output'],
            agent=self.input_parser(),
            output_file="input_analysis_result.json"
        )

    @task
    def technique_selection_task(self) -> Task:
        return Task(
            description=self.tasks_config['technique_selection_task']['description'],
            expected_output=self.tasks_config['technique_selection_task']['expected_output'],
            agent=self.technique_selector(),
            output_file="technique_selection_result.json"
        )

    @task
    def code_obfuscation_task(self) -> Task:
        return Task(
            description=self.tasks_config['code_obfuscation_task']['description'],
            expected_output=self.tasks_config['code_obfuscation_task']['expected_output'],
            agent=self.obfuscation_llm(),
            output_file=self.tasks_config['code_obfuscation_task']['output_file']
        )

    @crew
    def crew(self) -> Crew:
        return Crew(
            agents=[
                self.input_parser(),
                self.technique_selector(),
                self.obfuscation_llm()
            ],
            tasks=[
                self.input_analysis_task(),
                self.technique_selection_task(),
                self.code_obfuscation_task()
            ],
            process=Process.sequential,
            verbose=True,
        )
        
    def run():
        file_path = "samples/hello.py"  # or any dynamic path

        agents_config = load_yaml_config('config/agents.yaml')
        tasks_config = load_yaml_config('config/tasks.yaml')
        techniques_config = load_yaml_config('config/obfuscation_techniques.yaml')

        obfuscation_crew = ObfuscationCrew(
            agents_config=agents_config,
            tasks_config=tasks_config,
            techniques_config=techniques_config
        )

        obfuscation_crew.crew().kickoff(inputs={"file_path": file_path})


