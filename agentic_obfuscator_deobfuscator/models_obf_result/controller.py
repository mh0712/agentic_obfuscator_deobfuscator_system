import os
import shutil
from dotenv import load_dotenv
from pathlib import Path
from obfuscation_deobfuscation_crew.utils.utils import clean_output_file

# Load environment variables from .env file
load_dotenv()

# Define constants
MODEL_NAME = os.getenv("MODEL")
ROOT_DIR = os.getcwd()
RESULT_DIR = os.path.join(ROOT_DIR, "models_obf_result")

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

def get_file_extension(file_path: str) -> str:
    ext = Path(file_path).suffix.lower()
    if ext in ['.py', '.js']:
        return ext[1:]
    else:
        raise ValueError(f"Unsupported file extension: {ext}. Supported extensions are: .py, .js")


def copy_clean_outputs(inputFile) -> None:
    extension =  get_file_extension(inputFile)
    
    OUTPUT_FILES_TO_COPY = [     
        "complexity_analysis_output.json",
        "selected_techniques.json",
        "execution_validation_result.json",
        "semantic_equivalence_result.json",
        "feedback_loop_result.json",
        f"obfuscated_code.{extension}",
        f"corrected_obfuscated_code.{extension}",
        f"obfuscated_final.{extension}",
        f"deobfuscated_code.{extension}",
    ]


    if not MODEL_NAME:
        raise ValueError("MODEL environment variable not set in .env file")

    # Ensure base result directory exists
    os.makedirs(RESULT_DIR, exist_ok=True)

    # Create unique folder for this run
    output_folder = get_unique_folder_name(MODEL_NAME, RESULT_DIR)
    os.makedirs(output_folder, exist_ok=True)

    # Handle input files
    if (os.path.exists(inputFile)):
        shutil.copy(inputFile, os.path.join(output_folder, os.path.basename(inputFile)))
        print(f"[+] Copied input file {os.path.basename(inputFile)} to {output_folder}")
    else:
        print(f"[!] Warning: Input file {os.path.basename(inputFile)} not found in input/ folder.")

    # Handle output files
    for filename in OUTPUT_FILES_TO_COPY:
        source_path = os.path.join(ROOT_DIR, "output", filename)
        if os.path.exists(source_path):
            clean_output_file(str(source_path))
            shutil.move(source_path, os.path.join(output_folder, filename))
            print(f"[+] Moved output file {filename} to {output_folder}")
        else:
            print(f"[!] Warning: Output file {filename} not found in output/ folder.")

    print(f"[✓] All available files processed to: {output_folder}")
