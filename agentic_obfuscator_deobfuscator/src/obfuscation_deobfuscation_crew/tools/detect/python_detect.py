from pathlib import Path
import ast
from radon.complexity import cc_visit
from src.obfuscation_deobfuscation_crew.tools.detect.utils import has_encoded_strings, has_dynamic_execution, has_long_one_liner, has_suspicious_names

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


def analyze_python_complexity(code: str) -> dict:
    try:
        tree = ast.parse(code)
    except SyntaxError as e:
        return {"error": f"Syntax error in code: {str(e)}"}

    # Get the cyclomatic complexity for each function in the code
    complexity_scores = cc_visit(code)

    # Helper function to calculate the nesting depth of control structures
    def get_nesting_depth(node):
        if isinstance(node, (ast.If, ast.For, ast.While, ast.Try)):
            return 1 + max([get_nesting_depth(child) for child in ast.iter_child_nodes(node)], default=0)
        return 0

    # Calculate metrics
    num_functions = sum(isinstance(node, ast.FunctionDef) for node in ast.walk(tree))
    num_classes = sum(isinstance(node, ast.ClassDef) for node in ast.walk(tree))
    num_variables = sum(isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store) for node in ast.walk(tree))
    num_strings = sum(isinstance(node, ast.Str) for node in ast.walk(tree))  # for Python <3.8
    num_literals = sum(isinstance(node, ast.Constant) for node in ast.walk(tree))  # includes str, int, etc
    num_booleans = sum(isinstance(node, ast.Constant) and isinstance(node.value, bool) for node in ast.walk(tree))
    num_control_structures = sum(isinstance(node, (ast.If, ast.For, ast.While, ast.Try)) for node in ast.walk(tree))
    num_code_blocks = sum(isinstance(node, (ast.FunctionDef, ast.ClassDef)) for node in ast.walk(tree))
    num_lines = len(code.splitlines())

    # Calculate the maximum nesting depth
    nesting_depth = max([get_nesting_depth(node) for node in ast.walk(tree)])

    # Calculate overall cyclomatic complexity
    total_complexity = sum(c.complexity for c in complexity_scores)

    metrics = {
        "lines": num_lines,
        "functions": num_functions,
        "classes": num_classes,
        "cyclomatic_complexity": total_complexity,
        "variables": num_variables,
        "identifiers": num_variables + num_functions + num_classes,
        "strings": num_strings,
        "literals": num_literals,
        "booleans": num_booleans,
        "control_structures": num_control_structures,
        "code_blocks": num_code_blocks,
        "nesting_depth": nesting_depth,
    }

    # 🧠 Obfuscation-related applicability indicators (for the selector agent)
    applicability_flags = {
        "min_identifiers": metrics["identifiers"] >= 2,
        "min_functions": metrics["functions"] >= 1,
        "min_string_literals": metrics["strings"] >= 1,
        "min_literals": metrics["literals"] >= 2,
        "min_code_blocks": metrics["code_blocks"] >= 2,
        "min_control_structures": metrics["control_structures"] >= 1,
        "min_boolean_expressions": metrics["booleans"] >= 1,
        "max_nesting_depth": metrics["nesting_depth"] <= 5,  # flag to prevent too deep nesting
    }

    return {
        "complexity_metrics": metrics,
        "applicability_flags": applicability_flags
    }
    