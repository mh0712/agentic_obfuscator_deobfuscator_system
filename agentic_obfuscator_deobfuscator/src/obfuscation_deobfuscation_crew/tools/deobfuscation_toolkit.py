import base64
import re
import ast

def try_base64_decode(s: str) -> str:
    try:
        return base64.b64decode(s.encode()).decode()
    except Exception:
        return s  # return original if not decodable

def reverse_string(s: str) -> str:
    return s[::-1]

def is_valid_python(code: str) -> bool:
    try:
        ast.parse(code)
        return True
    except SyntaxError:
        return False

def unwrap_base64_reverse_chain(code: str) -> str:
    """
    Attempt to detect and decode patterns of:
    reverse(base64(reverse(base64(...))))
    """
    current = code
    for _ in range(3):  # support up to 3 layers
        if isinstance(current, bytes):
            current = current.decode()
        if 'base64' in current or re.search(r'[A-Za-z0-9+/=]{10,}', current):
            reversed_once = reverse_string(current)
            base64_decoded = try_base64_decode(reversed_once)
            if base64_decoded == current:
                break
            current = base64_decoded
        else:
            break
    return current
