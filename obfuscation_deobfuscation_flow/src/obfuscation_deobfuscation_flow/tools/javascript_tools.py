import os
import subprocess
import json

def is_js_code(code_path: str) -> bool:
    try:
        # Resolve long path (using UNC if needed)
        long_path = os.path.abspath(code_path)
        long_path = r"\\?\\" + long_path if len(long_path) > 260 else long_path
        
        result = subprocess.run(
            ["node", "C:\\Users\\celin\\Desktop\\usj\\FYP\\agentic_obfuscator_deobfuscator_system\\obfuscation_deobfuscation_flow\\src\\obfuscation_deobfuscation_flow\\tools\\scripts\\js_code_check.js", long_path],
            capture_output=True, text=True, check=True
        )
        return result
    except Exception as e:
        print(f"[!] JavaScript detection failed: {e}")
        return False
    
def is_obfuscated_js(file_path: str) -> bool:
    try:
        result = subprocess.run(
            ["node", "C:\\Users\\celin\\Desktop\\usj\\FYP\\agentic_obfuscator_deobfuscator_system\\obfuscation_deobfuscation_flow\\src\\obfuscation_deobfuscation_flow\\tools\\scripts\\js_obfuscation_check.js", file_path],
            capture_output=True, text=True, check=True
        )
        output = json.loads(result.stdout.strip())
        return output
    except Exception as e:
        print(f"[!] JavaScript obfuscation check failed: {e}")
        
import subprocess
import json

def analyze_javascript_complexity(code: str) -> dict:
    try:
        result = subprocess.run(
            ["node", "C:\\Users\\celin\\Desktop\\usj\\FYP\\agentic_obfuscator_deobfuscator_system\\obfuscation_deobfuscation_flow\\src\\obfuscation_deobfuscation_flow\\tools\\scripts\\complexity_analyser.js"],
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
            ["node", "C:\\Users\\celin\\Desktop\\usj\\FYP\\agentic_obfuscator_deobfuscator_system\\obfuscation_deobfuscation_flow\\src\\obfuscation_deobfuscation_flow\\tools\\scripts\\build_loader.js"],
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

def string_encryption_js(code: str) -> str:
    try:
        result = subprocess.run(
            ["node", "C:\\Users\\celin\\Desktop\\usj\\FYP\\agentic_obfuscator_deobfuscator_system\\obfuscation_deobfuscation_flow\\src\\obfuscation_deobfuscation_flow\\tools\\scripts\\string_encryption.js"],
            input=code,
            capture_output=True,
            text=True,
            check=True
        )
        output = result.stdout.strip()
        if not output:
            print("[!] No output from string encryption script.")
            if result.stderr:
                print("[stderr]:", result.stderr.strip())
            return None
        return output
    except subprocess.CalledProcessError as e:
        print(f"[!] JavaScript string encryption failed: {e}")
        print(f"[stderr]: {e.stderr.strip()}")
        return None
    
