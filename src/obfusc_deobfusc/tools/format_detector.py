import magic
from detect.python_detect import is_python_code, is_obfuscated_py
from detect.javascript_detect import is_js_code, is_obfuscated_js

def detect_code_format(file_path: str) -> dict:
    mime_type = magic.from_file(file_path, mime=True)
    print(f"[+] MIME Type: {mime_type}")

    if not mime_type.startswith("text"):
        return {"type": mime_type, "language": "binary", "obfuscated": None, "confidence": 0.0}

    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            code = f.read()
    except Exception:
        return {"type": mime_type, "language": "unknown", "obfuscated": None, "confidence": 0.0}

    # Check for Python code
    if is_python_code(file_path):
        result = is_obfuscated_py(file_path)  # Should return dict
        return {
            "type": "text/x-python",
            "language": "python",
            "obfuscated": result["obfuscated"],
            "confidence": result["confidence"]
        }

    # Check for JavaScript code
    if is_js_code(file_path):
        result = is_obfuscated_js(file_path)  # Should return dict
        return {
            "type": "text/javascript",
            "language": "javascript",
            "obfuscated": result["obfuscated"],
            "confidence": result["confidence"]
        }

    return {"type": mime_type, "language": "unknown", "obfuscated": None, "confidence": 0.0}

if __name__ == "__main__":
    # Example usage
    file_path = "path/to/your/file.js"  # Replace with your file path
    result = detect_code_format(file_path)
    print(result)