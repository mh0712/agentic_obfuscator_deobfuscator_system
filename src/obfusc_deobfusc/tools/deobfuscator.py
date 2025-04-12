import re

def deobfuscate_python(code: str) -> str:
    return code.replace("obf_print", "print").replace("var_", "original_")

def deobfuscate_js(code: str) -> str:
    return code.replace("obf_log", "console.log").replace("v_", "orig_")
