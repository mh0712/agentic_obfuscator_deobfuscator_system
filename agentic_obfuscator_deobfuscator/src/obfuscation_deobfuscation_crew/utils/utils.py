def remove_first_and_last_line(file_path):
    with open(file_path, 'r', encoding='utf-8') as f:
        lines = f.readlines()

    # Guard: Make sure there are at least 3 lines to remove first and last
    if len(lines) < 3:
        raise ValueError("File must contain at least 3 lines to safely remove the first and last lines.")

    # Remove the first and last lines
    updated_lines = lines[1:-1]

    # Overwrite the file with the new content
    with open(file_path, 'w', encoding='utf-8') as f:
        f.writelines(updated_lines)

    print(f"[+] Updated {file_path}: removed first and last lines.")

def get_extension_from_language(language: str) -> str:
    return {
        "python": "py",
        "javascript": "js",
        "binary": "bin",
        "unknown": "txt"
    }.get(language, "txt")