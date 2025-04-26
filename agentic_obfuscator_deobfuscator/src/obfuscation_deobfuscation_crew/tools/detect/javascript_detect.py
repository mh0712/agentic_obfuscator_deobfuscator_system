import os
import subprocess
import json

def is_js_code(code_path: str) -> bool:
    try:
        # Resolve long path (using UNC if needed)
        long_path = os.path.abspath(code_path)
        long_path = r"\\?\\" + long_path if len(long_path) > 260 else long_path
        
        result = subprocess.run(
            ["node", "./detect/scripts/js_code_check.js", long_path],
            capture_output=True, text=True, check=True
        )
        return result
    except Exception as e:
        print(f"[!] JavaScript detection failed: {e}")
        return False
    
def is_obfuscated_js(file_path: str) -> bool:
    try:
        result = subprocess.run(
            ["node", "./detect/scripts/js_obfuscation_check.js", file_path],
            capture_output=True, text=True, check=True
        )
        output = json.loads(result.stdout.strip())
        return output
    except Exception as e:
        print(f"[!] JavaScript obfuscation check failed: {e}")
        
def analyze_javascript_complexity(file_path: str) -> bool:
    try:
        result = subprocess.run(
            ["node", "src/obfuscation_deofuscation_crew/tools/detect/scripts/js_obfuscation_check.js", file_path],
            capture_output=True, text=True, check=True
        )
        output = json.loads(result.stdout.strip())
        return output
    except Exception as e:
        print(f"[!] JavaScript obfuscation check failed: {e}")