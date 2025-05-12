import ast
import astor  # to convert AST back to code
from typing import Dict

class RenameObfuscatedVariables(ast.NodeTransformer):
    def __init__(self):
        self.counter = 0
        self.mapping: Dict[str, str] = {}

    def _new_name(self):
        self.counter += 1
        return f"var_{self.counter}"

    def visit_Name(self, node):
        if isinstance(node.ctx, ast.Store) and len(node.id) <= 2:
            if node.id not in self.mapping:
                self.mapping[node.id] = self._new_name()
            node.id = self.mapping[node.id]
        elif isinstance(node.ctx, ast.Load) and node.id in self.mapping:
            node.id = self.mapping[node.id]
        return node

class RemoveDeadCode(ast.NodeTransformer):
    def visit_If(self, node):
        self.generic_visit(node)
        if isinstance(node.test, ast.Constant) and node.test.value == False:
            return None  # remove if False blocks
        return node

    def visit_FunctionDef(self, node):
        self.generic_visit(node)
        # Remove empty functions or those with only `pass`
        if len(node.body) == 0:
            return None
        if len(node.body) == 1 and isinstance(node.body[0], ast.Pass):
            return None
        return node

def deobfuscate_python_code(source_code: str) -> str:
    try:
        tree = ast.parse(source_code)

        # Step 1: Rename obfuscated vars
        tree = RenameObfuscatedVariables().visit(tree)

        # Step 2: Remove dead/empty constructs
        tree = RemoveDeadCode().visit(tree)

        # Step 3: Fix locations and regenerate source
        ast.fix_missing_locations(tree)
        return astor.to_source(tree)

    except Exception as e:
        return f"# Error during deobfuscation: {str(e)}\n\n{source_code}"

