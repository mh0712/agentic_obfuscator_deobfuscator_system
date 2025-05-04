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
class ObfuscationDeobfuscationCrew():
    agents_config = 'config/agents.yaml'
    tasks_config = 'config/tasks.yaml'
    

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
    def input_analysis_task(self) -> Task:
        return Task(
            description=self.tasks_config['input_analysis_task']['description'],
            expected_output=self.tasks_config['input_analysis_task']['expected_output'],
            agent=self.input_parser(),
            inputs={"file_path": "{{inputs.file_path}}"}
        )

    @task
    def code_complexity_analysis_task(self) -> Task:
        return Task(
            description=self.tasks_config['code_complexity_analysis_task']['description'],
            expected_output=self.tasks_config['code_complexity_analysis_task']['expected_output'],
            agent=self.complexity_analyzer(),
            context=[self.input_analysis_task()],
            output_file="complexity_analysis_output.json"
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
            output_file="execution_validator_result.json"
        )

    @task
    def semantic_equivalence_test_task(self) -> Task:
        return Task(
            description=self.tasks_config['semantic_equivalence_test_task']['description'],
            expected_output=self.tasks_config['semantic_equivalence_test_task']['expected_output'],
            agent=self.semantic_equivalence_validator(),
            context=[self.input_analysis_task(), self.code_obfuscation_task()],
            output_file="unit_test_comparison_result.json"
        )

    @task
    def feedback_loop_task(self) -> Task:
        return Task(
            description=self.tasks_config['feedback_loop_task']['description'],
            expected_output=self.tasks_config['feedback_loop_task']['expected_output'],
            agent=self.feedback_loop_agent(),
            context=[self.semantic_equivalence_test_task(), self.excecution_validator_task()],
            output_file="feedback_loop_result.json"
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



    @crew
    def crew(self) -> Crew:
        
        return Crew(
            agents=self.agents,
            tasks=self.tasks,
            process=Process.sequential,
            verbose=True,
        )


# crew.py
from crewai import Agent, Crew, Process, Task
from crewai.project import CrewBase, agent, crew, task
from crewai.tools import tool
from src.obfuscation_deobfuscation_crew.tools.binary_tools import run_ghidra_analysis
from crewai_tools import CodeInterpreterTool
import json
import os





@tool("ghidra_analysis_tool")
def ghidra_analysis_tool(file_path: str) -> dict:
    """
    Analyzes a binary using Ghidra, renames variables, and returns analysis.
    """
    return run_ghidra_analysis(file_path, script_name= "CFGJsonExporterScript.java", output_file="functionInfo.json")

@tool("find_free_memory_tool")
def find_free_memory_tool(file_path: str) -> dict:
    """
    Finds free memory in the binary file.
    """
    run_ghidra_analysis(file_path, script_name="FindWritableExecutableAddresses.java", output_file="free_memory.json")
    try:
        output_dir = "src//obfuscation_deobfuscation_crew//tools//ghidra_output"
        output_path = os.path.join(
            output_dir,
            "free_memory.json"
        )
        output_file_ge12 = os.path.join(
            output_dir,
            "free_memory_ge12.json"
        )
        output_file_lt12 = os.path.join(
            output_dir,
            "free_memory_lt12.json"
        )
        
        with open(output_path, 'r') as f:
            free_memory = json.load(f)
            
        ge12 = [entry for entry in free_memory if entry.get("length", 0) >= 12]
        lt12 = [entry for entry in free_memory if entry.get("length", 0) < 12]

        with open(output_file_ge12, "w") as f_ge12:
            json.dump(ge12, f_ge12, indent=4)
        with open(output_file_lt12, "w") as f_lt12:
            json.dump(lt12, f_lt12, indent=4)
            
    except FileNotFoundError as e:
        print(f"Error: {e}")
        return {"error": str(e)}

    return ge12, lt12  # Return the functions directly

@tool("find_conditional_branches_tool")
def find_conditional_branches_tool(file_path: str) -> dict:
    """
    Finds conditional branches in the binary file.
    """
    return run_ghidra_analysis(file_path, script_name="DetectConditionalBranches.java", output_file="conditional_branches.json")


@CrewBase
class BinaryObfuscationCrew:
    """Crew for automated binary obfuscation using GPT-4 and r2pipe."""
    agents_config = "config/agents.yaml"
    tasks_config = "config/tasks.yaml"

    # Obfuscation Strategist
    @agent
    def binary_analysis_agent(self) -> Agent:
        return Agent(
            config=self.agents_config['binary_analysis_agent'],
            verbose=True,
            tools=[ghidra_analysis_tool],
            allow_delegation=True,
        )

    @agent
    def binary_technique_planner_agent(self) -> Agent:
        return Agent(
            config=self.agents_config['binary_technique_planner_agent'],
            verbose=True,
        )
        
    @agent
    def binary_patch_planner_agent(self) -> Agent:
        return Agent(
            config=self.agents_config['binary_patch_planner_agent'],
            verbose=True,
            tools=[find_free_memory_tool, find_conditional_branches_tool],
        )
        
    @agent
    def ghidra_patch_agent(self) -> Agent:
        return Agent(
            config=self.agents_config['ghidra_patch_agent'],
            verbose=True,
        )
 
    @task
    def extraction_task(self) -> Task:
        return Task(
            config=self.tasks_config['extraction_task'],
            agent=self.binary_analysis_agent()
        )
        
    @task
    def binary_technique_plan_task(self) -> Task:
        return Task(
            config=self.tasks_config['binary_technique_plan_task'],
            agent=self.binary_technique_planner_agent(),
            context=[self.extraction_task()],
        )
        
    @task
    def plan_binary_obfuscation_patches_task(self) -> Task:
        return Task(
            config=self.tasks_config['plan_binary_obfuscation_patches'],
            agent=self.binary_patch_planner_agent(),
            context=[self.binary_technique_plan_task()],
        )
        

            
    @task 
    def apply_obfuscations_task(self) -> Task:
        return Task(
            config=self.tasks_config['apply_obfuscations_task'],
            agent=self.ghidra_patch_agent(),
            context=[self.plan_binary_obfuscation_patches_task()],
        )
        
    # The crew definition: defines how agents and tasks interact in sequence
    @crew
    def crew(self) -> Crew:
        return Crew(
            agents=self.agents,
            tasks=self.tasks,
            process=Process.sequential,
            verbose=True,
        )

