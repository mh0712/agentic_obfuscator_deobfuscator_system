import subprocess
import json
import os
import time
from pathlib import Path
import uuid

# === Path Definitions ===

GHIDRA_HEADLESS_PATH = Path(
    "C:/Users/celin/Downloads/ghidra_11.3.2_PUBLIC_20250415/ghidra_11.3.2_PUBLIC/support/analyzeHeadless.bat"
)

# Base path to your src directory
SRC_DIR = Path(
    "C:/Users/celin/Desktop/usj/FYP/agentic_obfuscator_deobfuscator_system/obfuscation_deobfuscation_flow/src"
)

SCRIPT_PATH = SRC_DIR / "obfuscation_deobfuscation_flow/crews/binaryobfuscationcrew/ghidra_scripts"
PROJECT_DIR = SRC_DIR.parent  # one level above "src" is your main project folder

# === File Wait Helper ===

def wait_for_file(file_path, timeout=60):
    start_time = time.time()
    while not Path(file_path).exists():
        if time.time() - start_time > timeout:
            raise TimeoutError(f"File not found within {timeout} seconds: {file_path}")
        print(f"Waiting for the file to appear at {file_path}...")
        time.sleep(1)
    print(f"File found: {file_path}")
    return file_path

# === Run Ghidra Analysis ===

def run_ghidra_analysis(file_path: str, script_name: str, output_file: str) -> dict:
    """
    Analyze and obfuscate binary variables using Ghidra headless decompilation.

    Args:
        file_path (str): Path to the binary file.
        script_name (str): Ghidra script to run.
        output_file (str): Output JSON file to be generated.

    Returns:
        dict: Analysis results.
    """
    cmd_analysis_binary = [
        str(GHIDRA_HEADLESS_PATH),
        str(PROJECT_DIR),
        'Ghidra_project_1',
        "-import", str(file_path),
        "-scriptPath", str(SCRIPT_PATH),
        "-postScript", script_name,
        "-deleteProject"
    ]
    
    subprocess.run(cmd_analysis_binary, check=True)

    try:
        output_path = SRC_DIR / "obfuscation_deobfuscation_flow/crews/binaryobfuscationcrew/ghidra_output" / output_file
        wait_for_file(output_path, timeout=60)
        
        with open(output_path, 'r') as f:
            functions = json.load(f)
            print(functions)

    except TimeoutError as e:
        print(e)
        return {"error": str(e)}

    return functions

def run_apply_obfuscation(file_path: str):
    # Generate a unique project name
    project_name = f"GhidraProject_{uuid.uuid4().hex[:8]}"
    
    # Step 1: Import and patch
    cmd_import_patch = [
        str(GHIDRA_HEADLESS_PATH),
        str(PROJECT_DIR),
        project_name,
        "-import", str(file_path),
        "-scriptPath", str(SCRIPT_PATH),
        "-postScript", "ApplyObfuscationTechniques.java"
    ]
    
    cmd_variable_renaming = [
        str(GHIDRA_HEADLESS_PATH),
        str(PROJECT_DIR),
        project_name,
        "-process",
        "-scriptPath", str(SCRIPT_PATH),
        "-postScript", "VariableRenaming.java",
    ]
    
    # Step 2: Run the Ghidra scripts
    subprocess.run(cmd_import_patch, check=True)
    subprocess.run(cmd_variable_renaming, check=True)

    return "Obfuscation applied successfully and saved to output file."

