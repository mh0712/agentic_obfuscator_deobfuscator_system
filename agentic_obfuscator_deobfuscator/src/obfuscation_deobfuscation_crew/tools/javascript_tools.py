import os
import subprocess
import json
from pathlib import Path

# Build script absolute paths dynamically
SCRIPTS_DIR = Path(__file__).resolve().parent / "scripts"
JS_CODE_CHECK = str(SCRIPTS_DIR / "js_code_check.js")
JS_OBFUSCATION_CHECK = str(SCRIPTS_DIR / "js_obfuscation_check.js")
COMPLEXITY_ANALYSER = str(SCRIPTS_DIR / "complexity_analyser.js")
BUILD_LOADER = str(SCRIPTS_DIR / "build_loader.js")

def is_js_code(code_path: str) -> bool:
    try:
        result = subprocess.run(
            ["node", JS_CODE_CHECK, code_path],
            capture_output=True, text=True, check=True
        )
        return result
    except Exception as e:
        print(f"[!] JavaScript detection failed: {e}")
        return False

def is_obfuscated_js(file_path: str) -> bool:
    try:
        result = subprocess.run(
            ["node", JS_OBFUSCATION_CHECK, file_path],
            capture_output=True, text=True, check=True
        )
        output = json.loads(result.stdout.strip())
        return output
    except Exception as e:
        print(f"[!] JavaScript obfuscation check failed: {e}")

def analyze_javascript_complexity(code: str) -> dict:
    try:
        result = subprocess.run(
            ["node", COMPLEXITY_ANALYSER],
            input=code,
            capture_output=True,
            text=True,
            check=True
        )
        output = json.loads(result.stdout.strip())
        return output
    except subprocess.CalledProcessError as e:
        print(f"[!] JavaScript complexity analysis failed: {e.stderr}")
        return {"error": e.stderr}
    except Exception as e:
        print(f"[!] Unexpected error during JavaScript complexity analysis: {e}")
        return {"error": str(e)}

def obfuscate_js(code: str) -> str:
    try:
        result = subprocess.run(
            ["node", BUILD_LOADER],
            input=code,
            capture_output=True,
            text=True,
            check=True
        )
        output = result.stdout.strip()
        if not output:
            print("[!] No output from obfuscation script.")
            return None
        return output
    except Exception as e:
        print(f"[!] JavaScript obfuscation failed: {e}")
        return None
