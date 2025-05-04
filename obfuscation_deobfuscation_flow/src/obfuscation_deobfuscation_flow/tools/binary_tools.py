import subprocess
import json
import os
import time


SCRIPT_PATH = "C:\\Users\\celin\\Desktop\\usj\\FYP\\agentic_obfuscator_deobfuscator_system\\agentic_obfuscator_deobfuscator\\ghidra_scripts"
GHIDRA_HEADLESS_PATH = r"C:\\Users\\celin\\Downloads\\ghidra_11.3.2_PUBLIC_20250415\\ghidra_11.3.2_PUBLIC\\support\\analyzeHeadless.bat"
PROJECT_DIR = "C:/Users/celin/Desktop/usj/FYP/agentic_obfuscator_deobfuscator_system/"

def wait_for_file(file_path, timeout=60):
    start_time = time.time()
    while not os.path.exists(file_path):
        if time.time() - start_time > timeout:
            raise TimeoutError(f"File not found within {timeout} seconds: {file_path}")
        print(f"Waiting for the file to appear at {file_path}...")
        time.sleep(1)
    print(f"File found: {file_path}")
    return file_path

def run_ghidra_analysis(file_path: str, script_name: str, output_file: str) -> dict:
    """
    Analyze and obfuscate binary variables using Ghidra headless decompilation.

    Args:
        file_path (str): Path to the binary file.

    Returns:
        dict: Analysis results.
    """
    
    cmd_analysis_binary = [
        GHIDRA_HEADLESS_PATH,
        PROJECT_DIR,
        'Ghidra_project_1',
        "-import", file_path,
        "-scriptPath", SCRIPT_PATH,
        "-postScript", script_name,
        "-deleteProject"  # Clean up after done
    ]
    subprocess.run(cmd_analysis_binary, check=True)

    try:
        output_path = os.path.join(
            PROJECT_DIR,
            "agentic_obfuscator_deobfuscator",
            "src",
            "obfuscation_deobfuscation_crew",
            "tools",
            "ghidra_output",
            output_file
        )
        wait_for_file(output_path, timeout=60)  # Wait for the file to be created
        with open(output_path, 'r') as f:
            functions = json.load(f)
            print(functions)  

    except TimeoutError as e:
        print(e)
        return {"error": str(e)}
    return functions  # Return the functions directly


if __name__ == "__main__":
    # Example usage
    binary_path = r"C:\Users\celin\Desktop\usj\FYP\agentic_obfuscator_deobfuscator_system\agentic_obfuscator_deobfuscator\binary.exe"
    run_ghidra_analysis(binary_path, "CFGJsonExporterScript.java", "functionInfo.json")