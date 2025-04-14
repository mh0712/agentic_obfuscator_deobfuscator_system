from pathlib import Path
import ast
from detect.utils import has_encoded_strings, has_dynamic_execution, has_long_one_liner, has_suspicious_names

def is_python_code(code_str: str) -> bool:
    try:
        with open(code_str, 'r', encoding='utf-8') as f:
            code = f.read()
        ast.parse(code)
        return True
    except SyntaxError:
        return False
    
def is_obfuscated_py(script_path):
    from pathlib import Path
    import ast

    code = Path(script_path).read_text(encoding="utf-8", errors="ignore")

    try:
        tree = ast.parse(code)
    except SyntaxError:
        print("[!] AST parse failed — possibly malformed or already obfuscated.")
        return {"obfuscated": True, "confidence": 1.0}

    features = {
        "encoded": has_encoded_strings(code),
        "dynamic_exec": has_dynamic_execution(tree),
        "long_lines": has_long_one_liner(code),
        "weird_names": has_suspicious_names(tree),
    }

    # Simple scoring system (can be improved with ML later)
    score = sum([0.25 if v else 0 for v in features.values()])
    return {
        "obfuscated": score >= 0.3,
        "confidence": round(min(score, 1.0), 2)
    }
