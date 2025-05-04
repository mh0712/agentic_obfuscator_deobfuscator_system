#!/usr/bin/env python
import os
import json
from typing import Optional
from pydantic import BaseModel
from crewai.flow.flow import Flow, start, listen
from obfuscation_deobfuscation_flow.tools.format_detector import detect_code_format
from obfuscation_deobfuscation_flow.crews.scriptobfuscationcrew.scriptobfuscationcrew import ScriptObfuscationCrew
from obfuscation_deobfuscation_flow.crews.binaryobfuscationcrew.binaryobfuscationcrew import BinaryObfuscationCrew

# === Flow State ===

class ObfuscationState(BaseModel):
    
    file_path: Optional[str] = None
    detected_format: Optional[dict] = None
    result: Optional[str] = None


# === Flow Definition ===

class ObfuscationRoutingFlow(Flow[ObfuscationState]):
    """Flow to detect format and launch appropriate obfuscation crew."""

    @start()
    def detect_format(self):
        """Run the flow via user input"""
        print("\n=== Obfuscation Routing Flow ===\n")
        file_path = input("Enter the path to the file you want to obfuscate: ")

        if not os.path.isfile(file_path):
            print(f"[❌] File not found: {file_path}")
            return

        """Detect format of the input file"""
        self.state.file_path = file_path
        print(f"\n[🧠] Detecting format for: {file_path}")
        result = detect_code_format(file_path)
        print(f"[📄] Detected: {result}")
        self.state.detected_format = result
        return result

    @listen(detect_format)
    def route_to_script_obfuscation(self, result):
        """If it's a script, run ScriptObfuscationCrew"""
        if result["language"] in ["python", "javascript"] and result["obfuscated"] == False:
            print("[🚀] Launching Script Obfuscation Crew...")
            
            extension = "py" if result["language"] == "python" else "js"

            with open(self.state.file_path, 'r', encoding='utf-8') as f:
                code = f.read()
            with open('src\\obfuscation_deobfuscation_flow\\crews\\scriptobfuscationcrew\\config\\script_obfuscation_techniques.json', 'r', encoding='utf-8') as f:
                techniques = f.read()

            inputs = {
                "file_path": self.state.file_path,
                "code": code,
                "techniques": techniques,
                "extension": extension
            }

            crew = ScriptObfuscationCrew().crew()
            output = crew.kickoff(inputs=inputs)
            self.state.result = output.raw if hasattr(output, "raw") else str(output)
            return self.state.result

    @listen(detect_format)
    def route_to_binary_obfuscation(self, result):
        """If it's binary, run BinaryObfuscationCrew"""
        if result["language"] == "binary" and result["obfuscated"] == False:
            print("[⚙️] Launching Binary Obfuscation Crew...")

            with open('src\\obfuscation_deobfuscation_flow\\crews\\binaryobfuscationcrew\\config\\binary_obfuscation_techniques.json', 'r', encoding='utf-8') as f:
                techniques = f.read()

            inputs = {
                "file_path": self.state.file_path,
                "techniques": techniques
            }

            crew = BinaryObfuscationCrew().crew()
            output = crew.kickoff(inputs=inputs)
            self.state.result = output.raw if hasattr(output, "raw") else str(output)
            return self.state.result

    @listen(detect_format)
    def fallback(self, result):
        """Handle unsupported or already-obfuscated cases"""
        if result["obfuscated"] == "true":
            print("[⛔] File appears to already be obfuscated.")
        elif result["language"] == "unknown":
            print("[❓] Could not detect or unsupported language.")
        self.state.result = "No crew launched."
        return self.state.result
    
    @listen(route_to_script_obfuscation)
    def finalize(self, result):
        """Final step to print the result"""
        if self.state.result:
            print(f"\n[✅] Obfuscation result:\n{self.state.result}")
        else:
            print("[❌] No obfuscation performed.")


# === CLI Entrypoint ===

def kickoff():
   
    try:
        flow = ObfuscationRoutingFlow()
        flow.kickoff()
        print("\n✅ Obfuscation flow completed.")
    except Exception as e:
        print(f"[🔥 ERROR] Something went wrong: {e}")


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
