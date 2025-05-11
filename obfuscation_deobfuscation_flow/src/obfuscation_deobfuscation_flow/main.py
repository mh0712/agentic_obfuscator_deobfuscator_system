
import os
import json
from typing import Optional
from pathlib import Path
from pydantic import BaseModel
from crewai.flow.flow import Flow, start, listen
from obfuscation_deobfuscation_flow.tools.format_detector import detect_code_format
from obfuscation_deobfuscation_flow.tools.python_tools import analyze_python_complexity, obfuscate_py
from obfuscation_deobfuscation_flow.tools.javascript_tools import analyze_javascript_complexity, obfuscate_js
from obfuscation_deobfuscation_flow.crews.scriptobfuscationcrew.scriptobfuscationcrew import ScriptObfuscationCrew
from obfuscation_deobfuscation_flow.crews.binaryobfuscationcrew.binaryobfuscationcrew import BinaryObfuscationCrew
from output.models_obf_result.controller import copy_outputs
import time
# === Flow State ===

class ObfuscationState(BaseModel):
    file_path: Optional[str] = None
    code: Optional[str] = None
    detected_format: Optional[dict] = None
    result: Optional[str] = None

# === Flow Definition ===

class ObfuscationRoutingFlow(Flow[ObfuscationState]):
    """Flow to detect format and launch appropriate obfuscation crew."""
    @start()
    def detect_format(self):
        print("\n=== Obfuscation Routing Flow ===\n")
        file_path = input("Enter the path to the file you want to obfuscate: ").strip()

        if not os.path.isfile(file_path):
            print(f"[❌] File not found: {file_path}")
            self.state.result = "File not found."
            return

        self.state.file_path = file_path

        print(f"\n[🧠] Detecting format for: {file_path}")
        result = detect_code_format(file_path)
        self.state.detected_format = result

        if not result or "language" not in result:
            print("[❓] Format detection failed or unsupported.")
            self.state.result = "Format detection failed."
            return

        print(f"[📄] Detected: {result}")

        # Only read source if it's not binary
        if result.get("language") != "binary":
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    self.state.code = f.read()
            except Exception as e:
                print(f"[❌] Error reading file: {e}")
                self.state.result = f"Failed to read source code: {e}"
                return

        return result

    @listen(detect_format)
    def analyze_and_route(self, result):
        """Handle analysis and routing based on format detection."""
        if result.get("obfuscated") is True:
            print("[⛔] File appears to already be obfuscated.")
            self.state.result = "No action taken. File is already obfuscated."
            return

        language = result.get("language", "unknown").lower()

        if language == "python":
            analysis = analyze_python_complexity(self.state.code)
            return self.route_to_script_obfuscation("py", "python", analysis)

        elif language == "javascript":
            analysis = analyze_javascript_complexity(self.state.code)
            return self.route_to_script_obfuscation("js", "javascript", analysis)

        elif language == "binary":
            return self.route_to_binary_obfuscation()

        else:
            print("[❓] Could not detect or unsupported language.")
            self.state.result = "Unsupported or unknown language."
            return

    def route_to_script_obfuscation(self, extension, language, complexity):
        print("[🚀] Launching Script Obfuscation Crew...")

        config_path = Path("src") / "obfuscation_deobfuscation_flow" / "crews" / "scriptobfuscationcrew" / "config" / "script_obfuscation_techniques.json"
        with open(config_path, 'r', encoding='utf-8') as f:
            techniques = f.read()

        inputs = {
            "code": self.state.code,
            "techniques": techniques,
            "extension": extension,
            "language": language,
            "complexity": complexity,
        }

        crew = ScriptObfuscationCrew().crew()
        output = crew.kickoff(inputs=inputs)

        # Optional: post-processing tools
        self.state.result = output.raw if hasattr(output, "raw") else str(output)
        # copy_outputs()
        print("[📦] Copying obfuscation results...")
        return self.state.result

    def route_to_binary_obfuscation(self):
        print("[⚙️] Launching Binary Obfuscation Crew...")

        config_path = Path("src") / "obfuscation_deobfuscation_flow" / "crews" / "binaryobfuscationcrew" / "config" / "binary_obfuscation_techniques.json"
        with open(config_path, 'r', encoding='utf-8') as f:
            techniques = f.read()

        inputs = {
            "binary_path": self.state.file_path,
            "techniques": techniques
        }

        crew = BinaryObfuscationCrew().crew()
        output = crew.kickoff(inputs=inputs)
        self.state.result = output.raw if hasattr(output, "raw") else str(output)
        return self.state.result
    
    @listen(analyze_and_route)
    def packing_obfuscated_code(self, result):
        """Final step to pack the obfuscated code"""
        result = self.state.detected_format
        py_language = result.get("language", "unknown").lower() == "python"
        if result and py_language:
            print("[📦] Packing obfuscated code...")
            with open("tests/string_encryption_obfuscation.py", "r") as f:
                code = f.read()
            packed_code = obfuscate_py(code)
            self.state.result = packed_code
            with open("tests/packed_code.py", "w") as f:
                f.write(packed_code)
            print(f"\n[📦] Packing obfuscated code:\n{self.state.result}")
        else:
            print("[❌] No obfuscation performed.")

    @listen(packing_obfuscated_code)
    def finalize(self, result):
        """Final step to print the result"""
        if self.state.result:
            print(f"\n[✅] Obfuscation result:\n{self.state.result}")
        else:
            print("[❌] No obfuscation performed.")

# === CLI Entrypoint ===

def kickoff():
    """Start the obfuscation flow and allow reruns until the user exits."""
    while True:
        try:
            start_time = time.perf_counter()
            flow = ObfuscationRoutingFlow()
            flow.kickoff()
            print("\n✅ Obfuscation flow completed.")
            end_time = time.perf_counter()  # End timing
            duration = end_time - start_time
            print(f"\n✅ Obfuscation flow completed in {duration:.4f} seconds.")

            rerun = input("\nWould you like to run another obfuscation? (y/n): ").strip().lower()
            if rerun != 'y':
                print("\n👋 Goodbye!")
                break

        except Exception as e:
            print(f"[🔥 ERROR] Something went wrong: {e}")
            break

def plot():
    """Generate a flow visualization"""
    try:
        flow = ObfuscationRoutingFlow()
        flow.plot("obfuscation_routing_flow")
        print("Flow visualization saved to obfuscation_routing_flow.html")
    except Exception as e:
        print(f"[🔥 ERROR] Something went wrong: {e}")

if __name__ == "__main__":
    kickoff()
