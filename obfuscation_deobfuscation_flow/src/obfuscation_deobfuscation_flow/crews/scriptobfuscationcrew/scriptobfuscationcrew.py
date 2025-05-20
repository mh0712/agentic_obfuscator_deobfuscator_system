

from crewai import Agent, Crew, Process, Task
from crewai.project import CrewBase, agent, crew, task

from src.obfuscation_deobfuscation_flow.tools.build_loader import obfuscate
from src.obfuscation_deobfuscation_flow.tools.encryption_tool import encrypt_strings_py
from src.obfuscation_deobfuscation_flow.tools.javascript_tools import string_encryption_js
from crewai.tools import BaseTool

# class PackerTool(BaseTool):
#     name: str = "packer_tool"
#     description: str = "Obfuscates and secures the given code into a fully secured standalone file using AES encryption, compression, bytecode transformation, and a self-executing loader."

#     def _run(self, code: str, language: str) -> str:
#         try:
#             return obfuscate(code, language=language)
#         except Exception as e:
#             print(f"[!] Obfuscation failed: {e}")
#             return ""

class EncryptionTool(BaseTool):
    name: str = "encryption_tool"
    description: str = "Encrypts the given code using a custom encryption method."

    def _run(self, code: str, language: str) -> str:
        try:
            if language == "python":
                return encrypt_strings_py(code)
            elif language == "javascript":
                return string_encryption_js(code)
            else:
                raise ValueError(f"Unsupported language: {language}")
        except Exception as e:
            print(f"[!] Encryption failed: {e}")
            return ""


@CrewBase
class ScriptObfuscationCrew():
    agents_config = 'config/agents.yaml'
    tasks_config = 'config/tasks.yaml'

    # === Tool Instances with result_as_answer set ===
    encryption_tool_instance = EncryptionTool(result_as_answer=True)
    # packer_tool_instance = PackerTool(result_as_answer=True)
    
    @agent
    def technique_selector(self) -> Agent:
        return Agent(
            config=self.agents_config['technique_selector'],
            verbose=True,
            # max_execution_time=120,  # Reduce timeout if possible
            # max_iter=3,  # Limit iterations
        )

    @agent
    def obfuscation_llm(self) -> Agent:
        return Agent(
            config=self.agents_config['obfuscation_llm'],
            verbose=True,
            # max_execution_time=300,
            # max_retry_limit=3,
        )

    @agent
    def string_encryptor_agent(self) -> Agent:
        return Agent(
            config=self.agents_config['string_encryptor_agent'],
            verbose=True,
            tools=[self.encryption_tool_instance],
            # max_execution_time=120,  # Reduce timeout if possible
            # max_iter=3,  # Limit iterations
            # max_rpm=None  # Remove rate limiting if not needed
        )

    # @agent
    # def packer_agent(self) -> Agent:
    #     return Agent(
    #         config=self.agents_config['packer_agent'],
    #         tools=[self.packer_tool_instance],
    #         verbose=True,
    #         allow_delegation=False,
    #         max_execution_time=120,  # Reduce timeout if possible
    #         max_iter=3,  # Limit iterations
    #         max_rpm=None  # Remove rate limiting if not needed
    #     )

    @task
    def technique_selection_task(self) -> Task:
        return Task(
            description=self.tasks_config['technique_selection_task']['description'],
            expected_output=self.tasks_config['technique_selection_task']['expected_output'],
            agent=self.technique_selector(),
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
    def string_encryptor_task(self) -> Task:
        return Task(
            description=self.tasks_config['string_encryptor_task']['description'],
            expected_output=self.tasks_config['string_encryptor_task']['expected_output'],
            agent=self.string_encryptor_agent(),
            context=[self.code_obfuscation_task()],
            output_file=self.tasks_config['string_encryptor_task']['output_file'],
        )

    # @task
    # def apply_packing_protection(self) -> Task:
    #     return Task(
    #         description=self.tasks_config['apply_packing_protection']['description'],
    #         expected_output=self.tasks_config['apply_packing_protection']['expected_output'],
    #         agent=self.packer_agent(),
    #         context=[self.string_encryptor_task()],
    #         output_file=self.tasks_config['apply_packing_protection']['output_file'],
    #     )

    @crew
    def crew(self) -> Crew:
    # Group tasks that can run in parallel
        group1 = [self.technique_selection_task()]
        group2 = [self.code_obfuscation_task(), self.string_encryptor_task()]
        # group3 = [self.apply_packing_protection()]
        
        return Crew(
            agents=self.agents,
            tasks=[*group1, *group2],
            process=Process.sequential,
            verbose=True,
        )
