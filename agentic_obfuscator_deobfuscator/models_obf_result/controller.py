import os
import shutil
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Define constants
MODEL_NAME = os.getenv("MODEL")
ROOT_DIR = os.getcwd()
RESULT_DIR = os.path.join(ROOT_DIR, "models_obf_result")
FILES_TO_COPY = [
    "complexity_analysis_output.json",
    "selected_techniques.json",
    "feedback_loop_result.json",
    "execution_validator_result.json",
    "final_obfuscated_code.py",
    "final_obfuscated_code.js",
    "unit_test_comparison_result.json",
    "unit_test_results.json",
    "technique_selection_result.yaml",
    "semantic_validation_result.json",
    "example.py",
    "example.js",
    "obfuscated_code.py",
    "obfuscated_code.js",
    "execution_comparison_result.json",
    "corrected_obfuscated_code.py",
    "obfuscated.py",
]

def get_unique_folder_name(base_name: str, parent_dir: str) -> str:
    """Generates a unique folder name by appending _1, _2, etc., if needed."""
    folder_path = os.path.join(parent_dir, base_name)
    if not os.path.exists(folder_path):
        return folder_path
    counter = 1
    while True:
        new_folder = f"{base_name}_{counter}"
        new_path = os.path.join(parent_dir, new_folder)
        if not os.path.exists(new_path):
            return new_path
        counter += 1

def copy_outputs():
    if not MODEL_NAME:
        raise ValueError("MODEL environment variable not set in .env file")

    # Ensure base result directory exists
    os.makedirs(RESULT_DIR, exist_ok=True)

    # Create unique folder for this run
    output_folder = get_unique_folder_name(MODEL_NAME, RESULT_DIR)
    os.makedirs(output_folder, exist_ok=True)

    # Copy files into the result folder
    for filename in FILES_TO_COPY:
        source_path = os.path.join(ROOT_DIR, filename)
        if filename == "example.py" or filename == "example.js":
            shutil.copy(source_path, os.path.join(output_folder, filename))
        elif os.path.exists(source_path):
            shutil.move(source_path, os.path.join(output_folder, filename))
            print(f"[+] Copied {filename} to {output_folder}")
        else:
            print(f"[!] Warning: {filename} not found in root directory.")
            continue

    print(f"[✓] All available files copied to: {output_folder}")

if __name__ == "__main__":
    copy_outputs()
