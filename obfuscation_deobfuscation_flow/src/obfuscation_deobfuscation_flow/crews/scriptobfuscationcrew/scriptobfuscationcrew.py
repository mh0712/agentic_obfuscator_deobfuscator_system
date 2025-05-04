import os
from crewai import Agent, Crew, Process, Task
from crewai.project import CrewBase, agent, crew, task
from obfuscation_deobfuscation_flow.tools.python_tools import analyze_python_complexity
from obfuscation_deobfuscation_flow.tools.javascript_tools import analyze_javascript_complexity
from src.obfuscation_deobfuscation_flow.tools.build_loader import obfuscate
from crewai.tools import tool
from crewai_tools import CodeInterpreterTool


@tool("complexity_analyzer_tool")
def complexity_analyzer_tool(code: str, language: str) -> dict:
    """
    Analyze the complexity of the given code, based on its language.
    
    Args:
        code (str): The code to be analyzed.
        language (str): The programming language ('python' or 'javascript').

    Returns:
        dict: A dictionary containing the complexity analysis results.
    """
    if language.lower() == "python":
        return analyze_python_complexity(code)

    elif language.lower() == "javascript":
        result = analyze_javascript_complexity(code)
        return result

    else:
        return {"error": f"Unsupported language: {language}"}


@tool("obfuxtreme_finalizer")
def obfuxtreme_finalizer(code: str,language: str) -> str:
    """
    Obfuscates and secures the given code using the Obfuxtreme tool.

    Args:
        code (str): The source code to be transformed.

    Returns:
        str: The obfuscated and secured code.
    """
    try:
        obfuscated_code = obfuscate(code,language)
        return obfuscated_code
    except Exception as e:
        print(f"[!] Obfuscation failed: {e}")
        return ""



@CrewBase
class ScriptObfuscationCrew():
    agents_config = 'config/agents.yaml'
    tasks_config = 'config/tasks.yaml'
    

    @agent
    def complexity_analyzer(self) -> Agent:
        return Agent(
            config=self.agents_config['complexity_analyzer'],
            verbose=True,
            tools=[complexity_analyzer_tool],
            allow_delegation=True,
        )

    @agent
    def technique_selector(self) -> Agent:
        return Agent(
            config=self.agents_config['technique_selector'],
            verbose=True,
            allow_delegation=True,
        )

    @agent
    def obfuscation_llm(self) -> Agent:
        return Agent(
            config=self.agents_config['obfuscation_llm'],
            verbose=True,
            max_execution_time=300,
            max_retry_limit=3,
        )

    @agent
    def execution_validator(self) -> Agent:
        return Agent(
            config=self.agents_config['execution_validator'],
            verbose=True,
            tools =[CodeInterpreterTool()]
        )
        
    @agent
    def semantic_equivalence_validator(self) -> Agent:
        return Agent(
            config=self.agents_config['semantic_equivalence_validator'],
            verbose=True,
            tools=[CodeInterpreterTool()],
            allow_delegation=True,
        )

    @agent
    def feedback_loop_agent(self) -> Agent:
        return Agent(
            config=self.agents_config['feedback_loop_agent'],
            verbose=True,
            max_execution_time=120,
            max_retry_limit=2
        )
    
    @agent
    def obfuxtreme_agent(self) -> Agent:
        return Agent(
            config=self.agents_config['obfuxtreme_agent'],
            tools=[obfuxtreme_finalizer],
            verbose=True,
            allow_delegation=False,
        )

    @task
    def code_complexity_analysis_task(self) -> Task:
        return Task(
            description=self.tasks_config['code_complexity_analysis_task']['description'],
            expected_output=self.tasks_config['code_complexity_analysis_task']['expected_output'],
            agent=self.complexity_analyzer(),
            output_file=self.tasks_config['code_complexity_analysis_task']['output_file'],
        )

    @task
    def technique_selection_task(self) -> Task:
        return Task(
            description=self.tasks_config['technique_selection_task']['description'],
            expected_output=self.tasks_config['technique_selection_task']['expected_output'],
            agent=self.technique_selector(),
            context=[self.code_complexity_analysis_task()],
            output_file=self.tasks_config['technique_selection_task']['output_file'],
        )

    @task
    def code_obfuscation_task(self) -> Task:
        return Task(
            description=self.tasks_config['code_obfuscation_task']['description'],
            expected_output=self.tasks_config['code_obfuscation_task']['expected_output'],
            agent=self.obfuscation_llm(),
            context=[self.technique_selection_task()],
            output_file=self.tasks_config['code_obfuscation_task']['output_file'],
        )

    @task
    def excecution_validator_task(self) -> Task:
        return Task(
            description=self.tasks_config['excecution_validator_task']['description'],
            expected_output=self.tasks_config['excecution_validator_task']['expected_output'],
            agent=self.execution_validator(),
            context=[self.code_obfuscation_task()],
            output_file=self.tasks_config['excecution_validator_task']['output_file'],
        )

    @task
    def semantic_equivalence_test_task(self) -> Task:
        return Task(
            description=self.tasks_config['semantic_equivalence_test_task']['description'],
            expected_output=self.tasks_config['semantic_equivalence_test_task']['expected_output'],
            agent=self.semantic_equivalence_validator(),
            context=[self.code_obfuscation_task()],
            output_file=self.tasks_config['semantic_equivalence_test_task']['output_file'],
        )

    @task
    def feedback_loop_task(self) -> Task:
        return Task(
            description=self.tasks_config['feedback_loop_task']['description'],
            expected_output=self.tasks_config['feedback_loop_task']['expected_output'],
            agent=self.feedback_loop_agent(),
            context=[self.semantic_equivalence_test_task(), self.excecution_validator_task()],
            output_file=self.tasks_config['feedback_loop_task']['output_file'],
        )

    @task
    def final_obfuscation_task(self) -> Task:
       
        return Task(
            description=self.tasks_config['final_obfuscation_task']['description'],
            expected_output=self.tasks_config['final_obfuscation_task']['expected_output'],
            agent=self.obfuscation_llm(),
            context=[self.feedback_loop_task()],
            output_file=self.tasks_config['final_obfuscation_task']['output_file'],
        )
        
    @task
    def apply_obfuxtreme_protection(self) -> Task:
        return Task(
            description=self.tasks_config['apply_obfuxtreme_protection']['description'],
            expected_output=self.tasks_config['apply_obfuxtreme_protection']['expected_output'],
            agent=self.obfuxtreme_agent(),
            context=[self.final_obfuscation_task()],
            output_file=self.tasks_config['apply_obfuxtreme_protection']['output_file'],
        )

    @crew
    def crew(self) -> Crew:
        return Crew(
            agents=self.agents,
            tasks=self.tasks,
            process=Process.sequential,
            verbose=True,
        )