import magic
from obfuscation_deobfuscation_flow.tools.python_tools import is_python_code, is_obfuscated_py
from obfuscation_deobfuscation_flow.tools.javascript_tools import is_js_code, is_obfuscated_js

BINARY_MIME_TYPES = {
    "application/x-executable",
    "application/x-pie-executable",
    "application/x-sharedlib",
    "application/x-dosexec",
    "application/x-elf",
    "application/x-mach-binary",
    "application/x-ms-dos-executable"
}

def detect_code_format(file_path: str) -> dict:
    try:
        mime_type = magic.from_file(file_path, mime=True)
    except Exception:
        mime_type = None

    # First: Check if MIME type indicates a binary
    if mime_type in BINARY_MIME_TYPES:
        return {"type": mime_type, "language": "binary", "obfuscated": False}

    # Fallback: Try to read as text
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            code = f.read()
    except Exception:
        return {"type": mime_type or "unknown", "language": "unknown", "obfuscated": None}

    # Try to detect source code types
    if is_python_code(file_path):
        result = is_obfuscated_py(file_path)
        return {
            "type": "text/x-python",
            "language": "python",
            "obfuscated": result["obfuscated"],
            "confidence": result["confidence"]
        }

    if is_js_code(file_path):
        result = is_obfuscated_js(file_path)
        return {
            "type": "text/javascript",
            "language": "javascript",
            "obfuscated": result["obfuscated"],
            "confidence": result["confidence"]
        }

    # Unknown
    return {"type": mime_type or "unknown", "language": "unknown", "obfuscated": None}
