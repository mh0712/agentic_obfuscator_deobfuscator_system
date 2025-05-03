import tempfile
import os
from crewai import Agent, Crew, Process, Task
from crewai.project import CrewBase, agent, crew, task
from src.obfuscation_deobfuscation_crew.tools.format_detector import detect_code_format
from obfuscation_deobfuscation_crew.tools.python_tools import analyze_python_complexity
from obfuscation_deobfuscation_crew.tools.javascript_tools import analyze_javascript_complexity
from src.obfuscation_deobfuscation_crew.tools.build_loader import obfuscate
from crewai.tools import tool
from crewai_tools import CodeInterpreterTool
import yaml


@tool("detect_code_format_tool")
def detect_code_format_tool(file_path: str) -> dict:
    """
    Detect the format of the code in the given file.
    Args:
        file_path (str): Path to the file to be analyzed.
    Returns:
        dict: A dictionary containing the detected format and the code itself.
    """
    result = detect_code_format(file_path)
    with open(file_path, "r", encoding="utf-8") as f:
        result["code"] = f.read()
    return result

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
class ObfuscationDeobfuscationCrew:
    def __init__(self, tasks_path='config/tasks.yaml', extension='js', operation='obfuscate'):
        self.extension = extension
        self.operation = operation

        # Local yaml loader
        def load_yaml(path):
            with open(path, "r", encoding="utf-8") as f:
                return yaml.safe_load(f)

        self.agents_config = load_yaml('src/obfuscation_deobfuscation_crew/config/agents.yaml')
        self.tasks_config = load_yaml(tasks_path)

        # Dynamically replace {extension} inside all output_file fields
        for task_key, task_val in self.tasks_config.items():
            if isinstance(task_val, dict) and 'output_file' in task_val:
                task_val['output_file'] = task_val['output_file'].replace('{extension}', self.extension)
                
    def detect_operation(self) -> str:
        # This assumes kickoff(inputs=...) always has "operation" key
        return self.operation if hasattr(self, 'operation') else 'obfuscate'
               
                
    @agent
    def input_parser(self) -> Agent:
        return Agent(
            config=self.agents_config['input_parser'],
            verbose=True,
            tools=[detect_code_format_tool],
            allow_delegation=True,
            llm=None,
        )

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
            tools=[CodeInterpreterTool()],
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
            max_retry_limit=2,
        )
    
    @agent
    def obfuxtreme_agent(self) -> Agent:
        return Agent(
            config=self.agents_config['obfuxtreme_agent'],
            tools=[obfuxtreme_finalizer],
            verbose=True,
            allow_delegation=False,
        )
        
    @agent
    def deobfuscation_llm(self) -> Agent:
        return Agent(
            config=self.agents_config['deobfuscation_llm'],  # Add in agents.yaml
            verbose=True,
            max_execution_time=300,
            max_retry_limit=3,
        )
    
    @agent
    def syntax_repair_agent(self) -> Agent:
        return Agent(
            config=self.agents_config['syntax_repair_agent'],
            verbose=True,
            max_execution_time=180,
            max_retry_limit=2,
        )


    @task
    def input_analysis_task(self) -> Task:
        return Task(
            description=self.tasks_config['input_analysis_task']['description'],
            expected_output=self.tasks_config['input_analysis_task']['expected_output'],
            agent=self.input_parser(),
            inputs={"file_path": "{{inputs.file_path}}"},
        )

    @task
    def code_complexity_analysis_task(self) -> Task:
        return Task(
            description=self.tasks_config['code_complexity_analysis_task']['description'],
            expected_output=self.tasks_config['code_complexity_analysis_task']['expected_output'],
            agent=self.complexity_analyzer(),
            context=[self.input_analysis_task()],
            output_file=self.tasks_config['code_complexity_analysis_task']['output_file'],
        )

    @task
    def technique_selection_task(self) -> Task:
        return Task(
            description=self.tasks_config['technique_selection_task']['description'],
            expected_output=self.tasks_config['technique_selection_task']['expected_output'],
            agent=self.technique_selector(),
            context=[self.input_analysis_task(), self.code_complexity_analysis_task()],
            output_file=self.tasks_config['technique_selection_task']['output_file'],
        )

    @task
    def code_obfuscation_task(self) -> Task:
        return Task(
            description=self.tasks_config['code_obfuscation_task']['description'],
            expected_output=self.tasks_config['code_obfuscation_task']['expected_output'],
            agent=self.obfuscation_llm(),
            context=[self.input_analysis_task(), self.technique_selection_task()],
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
            context=[self.input_analysis_task(), self.code_obfuscation_task()],
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
            context=[self.feedback_loop_task(), self.input_analysis_task()],
            output_file=self.tasks_config['final_obfuscation_task']['output_file'],
        )

    @task
    def apply_obfuxtreme_protection(self) -> Task:
        return Task(
            description=self.tasks_config['apply_obfuxtreme_protection']['description'],
            expected_output=self.tasks_config['apply_obfuxtreme_protection']['expected_output'],
            agent=self.obfuxtreme_agent(),
            context=[self.final_obfuscation_task(), self.input_analysis_task()],
            output_file=self.tasks_config['apply_obfuxtreme_protection']['output_file'],
        )
        
    @task
    def code_deobfuscation_task(self) -> Task:
        return Task(
            description=self.tasks_config['code_deobfuscation_task']['description'],
            expected_output=self.tasks_config['code_deobfuscation_task']['expected_output'],
            agent=self.deobfuscation_llm(),
            context=[self.input_analysis_task()],  # can expand this later
            output_file=self.tasks_config['code_deobfuscation_task']['output_file'],
        )
    
    @task
    def syntax_repair_task(self) -> Task:
        return Task(
            description="Repair syntactically malformed or incomplete code blocks produced during deobfuscation. Ensure the code is valid and complete.",
            expected_output="Cleaned code that is syntactically valid and executable.",
            agent=self.syntax_repair_agent(),
            context=[self.code_deobfuscation_task()],
            output_file=f"output/syntax_repair_output.{self.extension}"
        )


    @crew
    def crew(self) -> Crew:
        if self.extension not in ["py", "js"]:
            raise ValueError(f"Unsupported extension: {self.extension}")

        operation = self.detect_operation()  
        
        if operation == "obfuscate":
            self.agents = [
                self.input_parser(),
                self.complexity_analyzer(),
                self.technique_selector(),
                self.obfuscation_llm(),
                self.execution_validator(),
                self.semantic_equivalence_validator(),
                self.feedback_loop_agent(),
                self.obfuxtreme_agent()
            ]

            self.tasks = [
                self.input_analysis_task(),
                self.code_complexity_analysis_task(),
                self.technique_selection_task(),
                self.code_obfuscation_task(),
                self.excecution_validator_task(),
                self.semantic_equivalence_test_task(),
                self.feedback_loop_task(),
                self.final_obfuscation_task(),
                self.apply_obfuxtreme_protection()
            ]

        elif operation == "deobfuscate":
            self.agents = [
                self.input_parser(),
                self.deobfuscation_llm(),
                self.syntax_repair_agent()
            ]

            self.tasks = [
                self.input_analysis_task(),
                self.code_deobfuscation_task(),
                self.syntax_repair_task()
            ]

        else:
            raise ValueError(f"Unsupported operation: {operation}")

        return Crew(
            agents=self.agents,
            tasks=self.tasks,
            process=Process.sequential,
            verbose=True,
        )
