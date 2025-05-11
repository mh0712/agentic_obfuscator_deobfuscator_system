import ast
import base64
import marshal
import os
import random

import zlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from pathlib import Path
import ast
from radon.complexity import cc_visit
from obfuscation_deobfuscation_flow.tools.utils import has_encoded_strings, has_dynamic_execution, has_long_one_liner, has_suspicious_names

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


import ast
from radon.complexity import cc_visit

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
    num_print_statements = sum(
        isinstance(node, ast.Expr) and isinstance(node.value, ast.Call) and
        getattr(node.value.func, 'id', '') == 'print'
        for node in ast.walk(tree)
    )

    # Calculate the maximum nesting depth
    nesting_depth = max([get_nesting_depth(node) for node in ast.walk(tree)], default=0)

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
        "print_statements": num_print_statements,
    }

    # 🧠 Obfuscation-related applicability indicators (for the selector agent)
    applicability_flags = {
        "min_lines": metrics["lines"] >= 20,
        "min_identifiers": metrics["identifiers"] >= 3,
        "min_functions": metrics["functions"] >= 1,
        "min_string_literals": metrics["strings"] >= 1,
        "min_literals": metrics["literals"] >= 1,
        "min_code_blocks": metrics["code_blocks"] >= 2,
        "min_control_structures": metrics["control_structures"] >= 1,
        "min_boolean_expressions": metrics["booleans"] >= 1,
        "min_print_statements": metrics["print_statements"] >= 1,
        "max_nesting_depth": metrics["nesting_depth"] <= 5,
    }

    return {
        "complexity_metrics": metrics,
        "applicability_flags": applicability_flags
    }


# === CONFIG ===
NAME_LENGTH = 10
ALLOWED_CHARS = "abcdefghijklmnopqrstuvwxyz1234567890_"

# === Utility: Generate unique obfuscated names ===
def generate_obfuscated_names(real_names):
    used_names = set()
    name_map = {}

    def get_unique_name():
        while True:
            name = ''.join(random.choices(ALLOWED_CHARS, k=NAME_LENGTH))
            if name not in used_names and not name.isidentifier() is False:
                used_names.add(name)
                return name

    for real in real_names:
        name_map[real] = get_unique_name()

    return name_map

# === Encrypt string literals ===
def encrypt_literal(plaintext: str, key: bytes, iv: bytes) -> str:
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded = pad(plaintext.encode(), 16)
    encrypted = cipher.encrypt(padded)
    return base64.b85encode(encrypted).decode()

# === Build encrypted loader with dynamic names ===
def build_loader(encrypted_data, aes_key, iv, encrypted_strings, obf_names):
    return f"""
{obf_names['AES_KEY']} = {aes_key!r}
{obf_names['IV']} = {iv!r}

def {obf_names['init_decrypter']}():
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import unpad
    import base64
    def {obf_names['decryptor']}(enc_str):
        cipher = AES.new({obf_names['AES_KEY']}, AES.MODE_CBC, {obf_names['IV']})
        return unpad(cipher.decrypt(base64.b85decode(enc_str)), 16).decode()
    return {obf_names['decryptor']}
{obf_names['decode_string']} = {obf_names['init_decrypter']}()

{obf_names['sys']} = __import__({obf_names['decode_string']}('{encrypted_strings["sys"]}'))
{obf_names['os']} = __import__({obf_names['decode_string']}('{encrypted_strings["os"]}'))
{obf_names['base64']} = __import__({obf_names['decode_string']}('{encrypted_strings["base64"]}'))
{obf_names['hashlib']} = __import__({obf_names['decode_string']}('{encrypted_strings["hashlib"]}'))
{obf_names['marshal']} = __import__({obf_names['decode_string']}('{encrypted_strings["marshal"]}'))
{obf_names['zlib']} = __import__({obf_names['decode_string']}('{encrypted_strings["zlib"]}'))
{obf_names['traceback']} = __import__({obf_names['decode_string']}('{encrypted_strings["traceback"]}'))

_temp_crypto = __import__({obf_names['decode_string']}('{encrypted_strings["Crypto"]}'))
{obf_names['AES']} = getattr(_temp_crypto.Cipher, {obf_names['decode_string']}('{encrypted_strings["AES"]}'))
_temp_crypto_util = __import__({obf_names['decode_string']}('{encrypted_strings["Crypto"]}'))
{obf_names['unpad']} = getattr(_temp_crypto_util.Util.Padding, {obf_names['decode_string']}('{encrypted_strings["unpad"]}'))

def {obf_names['anti_debugger']}():
    # Decrypt the function call to `windll.kernel32.IsDebuggerPresent()` dynamically at runtime
    debugger_check_str = {obf_names['decode_string']}('{encrypted_strings["debugger_check"]}')
    windll = __import__({obf_names['decode_string']}('{encrypted_strings["ctypes"]}')).windll
    kernel32 = windll.kernel32
    IsDebuggerPresent = getattr(kernel32, {obf_names['decode_string']}('{encrypted_strings["IsDebuggerPresent"]}'))
    if {obf_names['sys']}.gettrace() or ({obf_names['os']}.name == {obf_names['decode_string']}('{encrypted_strings["nt"]}') and IsDebuggerPresent()):
        {obf_names['sys']}.exit(1)
{obf_names['anti_debugger']}()

def {obf_names['decrypt_str']}(data):
    try:
        cipher = {obf_names['AES']}.new({obf_names['AES_KEY']}, {obf_names['AES']}.MODE_CBC, {obf_names['IV']})
        return {obf_names['unpad']}(cipher.decrypt(data), 16).decode()
    except:
        return {obf_names['decode_string']}('{encrypted_strings["empty"]}')

def {obf_names['main']}():
    try:
        _encrypted = {encrypted_data!r}
        cipher = {obf_names['AES']}.new({obf_names['AES_KEY']}, {obf_names['AES']}.MODE_CBC, {obf_names['IV']})
        decoded = {obf_names['base64']}.b85decode(_encrypted)
        decrypted = {obf_names['unpad']}(cipher.decrypt(decoded), 16)
        decompressed = {obf_names['zlib']}.decompress(decrypted)
        exec({obf_names['marshal']}.loads(decompressed), {{
            **globals(),
            {obf_names['decode_string']}('{encrypted_strings["__name__"]}'): {obf_names['decode_string']}('{encrypted_strings["__main__"]}'),
            {obf_names['decode_string']}('{encrypted_strings["__builtins__"]}'): __builtins__,
            {obf_names['decode_string']}('{encrypted_strings["_decrypt_str"]}'): {obf_names['decrypt_str']}
        }})
    except Exception:
        getattr(__builtins__, {obf_names['decode_string']}('{encrypted_strings["print"]}'))({obf_names['decode_string']}('{encrypted_strings["Execution failed:"]}'))
        {obf_names['traceback']}.print_exc()
        {obf_names['sys']}.exit(1)

if globals().get({obf_names['decode_string']}('{encrypted_strings["__name__"]}')) == {obf_names['decode_string']}('{encrypted_strings["__main__"]}'):
    {obf_names['main']}()
"""

# === Main obfuscation engine ===
def obfuscate_py(code):
    transformed = marshal.dumps(compile(code, "<string>", "exec"))
    aes_key = os.urandom(16)
    iv = os.urandom(16)
    compressed = zlib.compress(transformed, level=9)
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    encrypted = base64.b85encode(cipher.encrypt(pad(compressed, 16))).decode()

    # Strings to encrypt for runtime decoding
    strings_to_encrypt = {
        "sys": None, "os": None, "base64": None, "hashlib": None, "marshal": None,
        "zlib": None, "traceback": None, "Crypto": None, "AES": None, "unpad": None,
        "nt": None, "ctypes": None, "__name__": None, "__main__": None,
        "__builtins__": None, "_decrypt_str": None, "print": None,
        "Execution failed:": None, "empty": "",
        "debugger_check": "windll.kernel32.IsDebuggerPresent()",  
        "IsDebuggerPresent": "IsDebuggerPresent"
    }

    encrypted_strings = {
        key: encrypt_literal(value if value is not None else key, aes_key, iv)
        for key, value in strings_to_encrypt.items()
    }

    # Dynamically rename identifiers
    real_identifiers = list(strings_to_encrypt.keys()) + [
        "decode_string", "decryptor", "init_decrypter", "AES_KEY", "IV",
        "anti_debugger", "decrypt_str", "main"
    ]
    obf_names = generate_obfuscated_names(real_identifiers)

    obfuscated_code = build_loader(encrypted, aes_key, iv, encrypted_strings, obf_names)
    print(f"[SUCCESS] Obfuscated with key: {aes_key.hex()}")
    return obfuscated_code

if __name__ == "__main__":
    # Example usage
    original_code = """print("Hello, World!") """
    obfuscated_code = obfuscate_py(original_code)
    
    # Save to file
    with open("obfuscated_script.py", "w") as f:
        f.write(obfuscated_code)