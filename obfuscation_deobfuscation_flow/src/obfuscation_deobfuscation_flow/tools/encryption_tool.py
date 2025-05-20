import ast
from string import printable

# --- Encryption Definitions (Unchanged) ---
SHORT_MAPPING = {
    "l": "str(str)[2]",
    "o": "str(eval)[16]",
    "c": "str(str)[1]",
    "a": "str(str)[3]",
    "s": "str(str)[4]",
    "i": "str(eval)[3]",
    "e": "str(eval)[19]",
    "b": "str(eval)[1]",
    "t": "str(eval)[5]",
    "f": "str(eval)[10]",
    "n": "str(eval)[8]",
    "r": "str(str)[10]",
    "(": "str(())[0]",
    ")": "str(())[1]",
    " ": "str(str)[6]",
    "[": "str([])[0]",
    "]": "str([])[1]",
}

CHAR_FORMAT_PREFIX = "eval(str(eval)[1]+str([])[0]+str("
CHAR_FORMAT_SUFFIX = ")+str([])[1])"

def char_to_expr(ch: str) -> str:
    if ch in SHORT_MAPPING:
        return SHORT_MAPPING[ch]
    idx = printable.index(ch)
    return f"{CHAR_FORMAT_PREFIX}{idx}{CHAR_FORMAT_SUFFIX}"

def generate_boilerplate():
    return (
        "exec(str(eval)[10]+str(str)[10]+str(eval)[16]+str(eval(str(str)[2]+str(eval)[16]+str(str)[1]+str(str)["
        "3]+str(str)[2]+str(str)[4]+str(())[0]+str(())[1]))[6]+str(str)[6]+str(str)[4]+str(eval)[5]+str(str)["
        "10]+str(eval)[3]+str(eval)[8]+str(eval(str(str)[2]+str(eval)[16]+str(str)[1]+str(str)[3]+str(str)[2]+str("
        "str)[4]+str(())[0]+str(())[1]))[50]+str(str)[6]+str(eval)[3]+str(eval(str(str)[2]+str(eval)[16]+str(str)["
        "1]+str(str)[3]+str(str)[2]+str(str)[4]+str(())[0]+str(())[1]))[6]+str(eval(str(str)[2]+str(eval)[16]+str("
        "str)[1]+str(str)[3]+str(str)[2]+str(str)[4]+str(())[0]+str(())[1]))[45]+str(eval)[16]+str(str)[10]+str("
        "eval)[5]+str(str)[6]+str(eval(str(str)[2]+str(eval)[16]+str(str)[1]+str(str)[3]+str(str)[2]+str(str)["
        "4]+str(())[0]+str(())[1]))[45]+str(str)[10]+str(eval)[3]+str(eval)[8]+str(eval)[5]+str(str)[3]+str(eval)["
        "1]+str(str)[2]+str(eval)[19]+str(str)[6]+str(str)[3]+str(str)[4]+str(str)[6]+str(eval)[1])\n"
    )

def inflate(input_code: str) -> str:
    if '"""' in input_code:
        raise ValueError("Triple quotes not supported, use ''' instead")

    output_code = generate_boilerplate()
    char_expressions = [char_to_expr(c) for c in input_code]
    output_code += f"exec({'+'.join(char_expressions)})\n"
    return output_code

# --- AST Transformer for Obfuscation ---
class Obfuscator(ast.NodeTransformer):
    def visit_Assign(self, node):
        # Only obfuscate string assignments
        if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            line_src = ast.unparse(node).strip()
            obf_code = inflate(line_src)
            # Ensure the indentation is kept for the obfuscated code
            obfuscated_node = ast.Expr(value=ast.Call(
                func=ast.Name(id='exec', ctx=ast.Load()),
                args=[ast.Constant(value=obf_code)],
                keywords=[]
            ))
            return obfuscated_node
        return self.generic_visit(node)

    def visit_Expr(self, node):
        # Only obfuscate print(...) expressions
        if isinstance(node.value, ast.Call) and getattr(node.value.func, 'id', '') == 'print':
            line_src = ast.unparse(node).strip()
            obf_code = inflate(line_src)
            # Ensure the indentation is kept for the obfuscated code
            obfuscated_node = ast.Expr(value=ast.Call(
                func=ast.Name(id='exec', ctx=ast.Load()),
                args=[ast.Constant(value=obf_code)],
                keywords=[]
            ))
            return obfuscated_node
        return self.generic_visit(node)

# --- Apply AST-based Obfuscation ---
def encrypt_strings_py(source: str) -> str:
    tree = ast.parse(source)
    transformer = Obfuscator()
    obfuscated_tree = transformer.visit(tree)
    ast.fix_missing_locations(obfuscated_tree)
    return ast.unparse(obfuscated_tree)

