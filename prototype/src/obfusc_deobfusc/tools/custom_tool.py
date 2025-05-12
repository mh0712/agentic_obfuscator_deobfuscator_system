from crewai.tools import BaseTool
from tools.format_detector import detect_code_format
from tools.obfuscator import obfuscate_python, obfuscate_js
from tools.deobfuscator import deobfuscate_python, deobfuscate_js

class DetectFormatTool(BaseTool):
    name: str = "Code Format Detector"
    description: str = "Detects if the code file is Python, JavaScript, or binary."

    def _run(self, input: str) -> str:
        return detect_code_format(input)


# class ObfuscateTool(BaseTool):
#     name: str = "Code Obfuscator"
#     description: str = "Obfuscates Python or JavaScript code based on its language."

#     def _run(self, input: str) -> str:
#         with open(input, "r", encoding="utf-8") as f:
#             code = f.read()
#         lang = detect_code_format(input)
#         if lang == "python":
#             return obfuscate_python(code)
#         elif lang == "javascript":
#             return obfuscate_js(code)
#         return "Unsupported language"

# class DeobfuscateTool(BaseTool):
#     name: str = "Code Deobfuscator"
#     description: str = "Deobfuscates Python or JavaScript code."

#     def _run(self, input: str) -> str:
#         with open(input, "r", encoding="utf-8") as f:
#             code = f.read()
#         lang = detect_code_format(input)
#         if lang == "python":
#             return deobfuscate_python(code)
#         elif lang == "javascript":
#             return deobfuscate_js(code)
#         return "Unsupported language"
