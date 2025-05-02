import os

def clean_output_file(file_path):
    if not os.path.exists(file_path):
        print(f"[!] Warning: file {file_path} does not exist. Skipping clean_output_file.")
        return

    with open(file_path, 'r', encoding='utf-8') as f:
        lines = f.readlines()

    cleaned_lines = []
    inside_code_block = False

    for line in lines:
        stripped = line.strip()
        if stripped.startswith("```"):  # Start or end of code block
            inside_code_block = not inside_code_block
            continue
        if inside_code_block:
            cleaned_lines.append(line)

    # Fallback: if no code block detected, keep original lines
    if not cleaned_lines and lines:
        cleaned_lines = lines

    # Trim leading/trailing empty lines
    while cleaned_lines and cleaned_lines[0].strip() == "":
        cleaned_lines.pop(0)
    while cleaned_lines and cleaned_lines[-1].strip() == "":
        cleaned_lines.pop()

    with open(file_path, 'w', encoding='utf-8') as f:
        f.writelines(cleaned_lines)

    print(f"[+] Cleaned output file: {file_path}")

def get_extension_from_language(language: str) -> str:
    return {
        "python": "py",
        "javascript": "js",
        "binary": "bin",
        "unknown": "txt"
    }.get(language, "txt")
