from crewai import Agent, Crew, Process, Task
from crewai.project import CrewBase, agent, crew, task

# If you want to run a snippet of code before or after the crew starts,
# you can use the @before_kickoff and @after_kickoff decorators
# https://docs.crewai.com/concepts/crews#example-crew-class-with-decorators

@CrewBase
class Scriptdeobfuscationcrew():
    """Scriptdeobfuscationcrew crew"""

    # Learn more about YAML configuration files here:
    # Agents: https://docs.crewai.com/concepts/agents#yaml-configuration-recommended
    # Tasks: https://docs.crewai.com/concepts/tasks#yaml-configuration-recommended
    agents_config = 'config/agents.yaml'
    tasks_config = 'config/tasks.yaml'

    # If you would like to add tools to your agents, you can learn more about it here:
    # https://docs.crewai.com/concepts/agents#agent-tools
    @agent
    def technique_selector_deobfuscation(self) -> Agent:
        return Agent(
            config=self.agents_config['technique_selector_deobfuscation'],
            verbose=True,
            allow_delegation=True,
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



    # To learn more about structured task outputs,
    # task dependencies, and task callbacks, check out the documentation:
    # https://docs.crewai.com/concepts/tasks#overview-of-a-task
    @task
    def technique_selector_deobfuscation_task(self) -> Task:
        return Task(
            description=self.tasks_config['technique_selector_deobfuscation_task']['description'],
            expected_output=self.tasks_config['technique_selector_deobfuscation_task']['expected_output'],
            agent=self.technique_selector_deobfuscation(),
            context=[self.input_analysis_task(), self.code_complexity_analysis_task()],
            output_file=self.tasks_config['technique_selector_deobfuscation_task']['output_file'],
        )   
    @task
    def code_deobfuscation_task(self) -> Task:
        return Task(
            description=self.tasks_config['code_deobfuscation_task']['description'],
            expected_output=self.tasks_config['code_deobfuscation_task']['expected_output'],
            agent=self.deobfuscation_llm(),
            context=[self.input_analysis_task(), self.technique_selector_deobfuscation_task()],  # can expand this later
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
        """Creates the Scriptdeobfuscationcrew crew"""
        # To learn how to add knowledge sources to your crew, check out the documentation:
        # https://docs.crewai.com/concepts/knowledge#what-is-knowledge

        return Crew(
            agents=self.agents, # Automatically created by the @agent decorator
            tasks=self.tasks, # Automatically created by the @task decorator
            process=Process.sequential,
            verbose=True,
            # process=Process.hierarchical, # In case you wanna use that instead https://docs.crewai.com/how-to/Hierarchical/
        )
