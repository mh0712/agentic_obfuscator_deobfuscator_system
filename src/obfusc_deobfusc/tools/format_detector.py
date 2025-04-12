import os
import magic
import re

def detect_code_format(file_path: str) -> str:
    # Use libmagic to check binary type
    file_type = magic.from_file(file_path, mime=True)
    if "text" not in file_type:
        return "binary"

    # If it's text, inspect content
    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        code = f.read()

    if re.search(r"^\s*import\s|\s*def\s|\s*print\s*\(", code, re.M):
        return "python"
    elif re.search(r"^\s*(function|let|const|var)\s", code, re.M):
        return "javascript"
    elif re.search(r"#include\s|int\s+main", code, re.M):
        return "c++"

    return "unknown"

def is_obfuscated(code: str) -> bool:
    # Naive heuristics: weird variable names, lots of hashes, no spaces, etc.
    suspicious_patterns = [
        r"var_\d+", r"v_\d+", r"_[a-zA-Z0-9]{5,}", r"eval\(", r"obf_", r"minified"
    ]
    matches = sum(bool(re.search(p, code)) for p in suspicious_patterns)
    return matches >= 2  # Adjust threshold
