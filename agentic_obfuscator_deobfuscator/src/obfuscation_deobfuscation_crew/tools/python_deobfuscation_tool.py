from crewai_tools import BaseTool
from .python_deobfuscator import deobfuscate_python_code

class PythonDeobfuscationTool(BaseTool):
    name = "python_deobfuscator"
    description = "Deobfuscates Python code using AST analysis and variable renaming."

    def _run(self, code: str) -> str:
        print("🔍 [Deobfuscator] Original code:\n", code)
        result = deobfuscate_python_code(code)
        print("✅ [Deobfuscator] Deobfuscated code:\n", result)
        return result
