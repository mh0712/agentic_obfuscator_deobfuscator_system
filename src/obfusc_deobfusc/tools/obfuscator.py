import ast
import astor
import random
import string
import re

class RenameVars(ast.NodeTransformer):
    def __init__(self):
        self.mapping = {}

    def obf_name(self, name):
        if name not in self.mapping:
            self.mapping[name] = ''.join(random.choices(string.ascii_letters, k=6))
        return self.mapping[name]

    def visit_FunctionDef(self, node):
        node.name = self.obf_name(node.name)
        self.generic_visit(node)
        return node

    def visit_Name(self, node):
        if isinstance(node.ctx, ast.Store) or isinstance(node.ctx, ast.Load):
            node.id = self.obf_name(node.id)
        return node

def obfuscate_python(code: str) -> str:
    try:
        tree = ast.parse(code)
        obfuscator = RenameVars()
        obfuscated_tree = obfuscator.visit(tree)
        return astor.to_source(obfuscated_tree)
    except Exception as e:
        return f"# Obfuscation Error: {e}"


def obfuscate_js(code: str) -> str:
    def obf_var(match):
        name = match.group(1)
        return f"var _{hash(name) % 99999}"

    code = re.sub(r"\bvar\s+([a-zA-Z_]\w*)", obf_var, code)
    code = re.sub(r"\bfunction\s+([a-zA-Z_]\w*)", lambda m: f"function _{hash(m.group(1)) % 99999}", code)
    return code
