from crewai import Agent, Crew, Process, Task
from crewai.project import CrewBase, agent, crew, task
from crewai.tools import tool
from src.obfuscation_deobfuscation_flow.tools.binary_tools import run_ghidra_analysis, run_apply_obfuscation
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
        output_dir = "C:\\Users\\celin\\Desktop\\usj\\FYP\\agentic_obfuscator_deobfuscator_system\\obfuscation_deobfuscation_flow\\src\\obfuscation_deobfuscation_flow\\crews\\binaryobfuscationcrew\\ghidra_output\\"
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
@tool("run_apply_obfuscation_tool")
def run_apply_obfuscation_tool(file_path: str) -> dict:
    """
    Applies obfuscations to the binary file using Ghidra.
    """
    return run_apply_obfuscation(file_path)

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
        
    
    @agent
    def ghidra_script_runner_agent(self) -> Agent:
        return Agent(
            config=self.agents_config['ghidra_script_runner_agent'],
            verbose=True,
            tools=[run_apply_obfuscation_tool],
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
        
    @task
    def ghidra_script_runner_task(self) -> Task:
        return Task(
            config=self.tasks_config['ghidra_script_runner_task'],
            agent=self.ghidra_script_runner_agent(),
            context=[self.apply_obfuscations_task()],
        )
        
    @crew
    def crew(self) -> Crew:
        return Crew(
            agents=self.agents,
            tasks=self.tasks,
            process=Process.sequential,
            verbose=True,
        )

