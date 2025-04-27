import os

def remove_first_and_last_line(file_path):
    if not os.path.exists(file_path):
        print(f"[!] Warning: file {file_path} does not exist. Skipping remove_first_and_last_line.")
        return
    
    with open(file_path, 'r', encoding='utf-8') as f:
        lines = f.readlines()

    if len(lines) <= 2:
        print(f"[!] Warning: file {file_path} has too few lines to process.")
        return
    
    with open(file_path, 'w', encoding='utf-8') as f:
        f.writelines(lines[1:-1])

    print(f"[+] Updated {file_path}: removed first and last lines.")

def get_extension_from_language(language: str) -> str:
    return {
        "python": "py",
        "javascript": "js",
        "binary": "bin",
        "unknown": "txt"
    }.get(language, "txt")
