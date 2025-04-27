

from crewai.tools import BaseTool
from crewai import LLM, Agent, Task, Crew

class ApplyObfuscationTool(BaseTool):
    name: str = "Apply Obfuscation"
    description: str = "Uses an LLM to apply obfuscation based on a prompt and code input."

    def _run(self, code: str, language: str, technique: dict) -> str:
        prompt_template = technique.get("llm_prompt", "")
        parameters = technique.get("parameters", {})

        # Format the prompt
        prompt = prompt_template.format(
            code=code,
            language=language,
            parameters=parameters
        )

        # Run the LLM prompt
        llm = LLM(model="groq/llama-3.3-70b-versatile")
        return llm.invoke(prompt)
