import ast
import base64
import zlib
import math
import re


def is_base64(s):
    try:
        return base64.b64encode(base64.b64decode(s)).decode() == s
    except Exception:
        return False

def is_hex(s):
    return re.fullmatch(r"(0x)?[0-9a-fA-F]{20,}", s) is not None

def is_zlib_compressed(s):
    try:
        zlib.decompress(base64.b64decode(s))
        return True
    except:
        return False

def entropy(s):
    """Shannon entropy of a string"""
    prob = [float(s.count(c)) / len(s) for c in set(s)]
    return -sum(p * math.log(p, 2) for p in prob)

def has_encoded_strings(code):
    candidates = re.findall(r'(?:["\'])([A-Za-z0-9+/=]{20,})(?:["\'])', code)
    for s in candidates:
        if is_base64(s) or is_zlib_compressed(s) or is_hex(s):
            return True
        if entropy(s) > 4.5:
            return True
    return False

def has_dynamic_execution(ast_tree):
    dynamic_calls = {'eval', 'exec', 'compile', '__import__'}
    for node in ast.walk(ast_tree):
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name) and node.func.id in dynamic_calls:
                return True
            elif isinstance(node.func, ast.Attribute):
                if isinstance(node.func.value, ast.Name) and node.func.attr in dynamic_calls:
                    return True
    return False

def has_long_one_liner(code):
    return any(len(line) > 300 for line in code.splitlines())

def has_suspicious_names(ast_tree):
    pattern = re.compile(r'^[A-Za-z0-9]{15,}$')
    for node in ast.walk(ast_tree):
        if isinstance(node, (ast.FunctionDef, ast.Name, ast.arg)):
            name = getattr(node, "id", None) or getattr(node, "name", None) or getattr(node, "arg", None)
            if name and pattern.match(name):
                return True
    return False