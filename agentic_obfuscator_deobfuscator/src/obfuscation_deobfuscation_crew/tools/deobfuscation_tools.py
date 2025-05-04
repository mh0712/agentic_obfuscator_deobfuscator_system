import base64
import re
import ast
import astor

# --- BASE64 TOOLS ---

def is_base64(s: str) -> bool:
    pattern = r'^[A-Za-z0-9+/=]{8,}$'
    return re.fullmatch(pattern, s) is not None

def try_base64_decode(s: str) -> str:
    try:
        return base64.b64decode(s.encode()).decode()
    except Exception:
        return s

def extract_base64_strings(code: str) -> list:
    pattern = r'["\']([A-Za-z0-9+/=]{8,})["\']'
    return re.findall(pattern, code)

def decode_all_base64_strings(code: str) -> str:
    strings = extract_base64_strings(code)
    for s in strings:
        decoded = try_base64_decode(s)
        code = code.replace(s, decoded)
    return code
# --- AST STRING EXTRACTION (PYTHON) ---

def extract_strings_from_ast(code: str) -> list:
    try:
        tree = ast.parse(code)
        return [node.s for node in ast.walk(tree) if isinstance(node, ast.Str)]
    except SyntaxError:
        return []
# --- FUNCTION INLINING & LAMBDA-TO-DEF (PYTHON) ---

class LambdaToDefTransformer(ast.NodeTransformer):
    def visit_Assign(self, node):
        if isinstance(node.value, ast.Lambda):
            try:
                func_name = node.targets[0].id
                args = node.value.args
                body = [ast.Return(node.value.body)]
                return ast.FunctionDef(
                    name=func_name,
                    args=args,
                    body=body,
                    decorator_list=[]
                )
            except Exception:
                return node
        return node

def convert_lambdas_to_defs(code: str) -> str:
    try:
        tree = ast.parse(code)
        transformed = LambdaToDefTransformer().visit(tree)
        return astor.to_source(transformed)
    except Exception:
        return code
# --- EVAL / EXEC UNWRAPPING (PYTHON & JS) ---

def unwrap_eval_exec(code: str) -> str:
    pattern = r"(eval|exec)\((.+?)\)"
    matches = re.findall(pattern, code)
    for func, inner in matches:
        cleaned = inner.strip('"').strip("'")
        code = code.replace(f"{func}({inner})", cleaned)
    return code
# --- LITERAL & SYMBOL RESOLUTION (PYTHON) ---

def resolve_literals(code: str) -> str:
    try:
        tree = ast.parse(code)
        return ast.unparse(tree)
    except Exception:
        return code
