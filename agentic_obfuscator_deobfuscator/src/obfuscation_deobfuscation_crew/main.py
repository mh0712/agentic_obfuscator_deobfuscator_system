#!/usr/bin/env python
import os
import sys
import json
import string
import warnings
from pathlib import Path
from datetime import datetime
from obfuscation_deobfuscation_crew.crew import ObfuscationDeobfuscationCrew
from models_obf_result.controller import copy_outputs
from obfuscation_deobfuscation_crew.config import config
from obfuscation_deobfuscation_crew.utils.utils import remove_first_and_last_line


warnings.filterwarnings("ignore", category=SyntaxWarning, module="pysbd")

# Calculate root path
ROOT_DIR = Path(__file__).resolve().parent.parent.parent
INPUT_DIR = ROOT_DIR / "input"
OUTPUT_DIR = ROOT_DIR / "output"

def choose_input_file():
    input_files = [f for f in os.listdir(INPUT_DIR) if os.path.isfile(INPUT_DIR / f)]

    if not input_files:
        print("[!] No input files found in 'input/' folder.")
        sys.exit(1)

    # Map letters (a, b, c, ...) to files
    available_keys = list(string.ascii_lowercase)
    letter_to_file = {}

    print("\n[+] Available input files:")
    for idx, filename in enumerate(input_files):
        if idx >= len(available_keys):
            break
        key = available_keys[idx]
        letter_to_file[key] = filename
        print(f"[{key}] {filename}")

    while True:
        choice = input("\nChoose a file (a/b/c...): ").strip().lower()
        if choice in letter_to_file:
            selected_file = INPUT_DIR / letter_to_file[choice]
            print(f"[+] Selected file: {letter_to_file[choice]}")
            return str(selected_file)
        else:
            print("[!] Invalid choice. Please select a valid letter.")

def get_file_extension(file_path: str) -> str:
    ext = Path(file_path).suffix.lower()
    if ext in ['.py', '.js']:
        return ext[1:]
    else:
        raise ValueError(f"Unsupported file extension: {ext}. Supported extensions are: .py, .js")

def run():
    file_path = (
        sys.argv[2]
        if len(sys.argv) > 2
        else choose_input_file()
    )

    # Dynamically detect extension
    extension = get_file_extension(file_path)
    print(f"[+] Detected file extension: {extension}")

    with open(file_path, "r", encoding="utf-8") as f:
        code = f.read()

    techniques_path = ROOT_DIR / "src" / "obfuscation_deobfuscation_crew" / "config" / "obfuscation_techniques.json"
    with open(techniques_path, "r", encoding="utf-8") as f:
        techniques = json.load(f)

    # Choose tasks.yaml dynamically
    tasks_file = ROOT_DIR / "src" / "obfuscation_deobfuscation_crew" / "config" / f"tasks_{extension}.yaml"
    if not tasks_file.exists():
        tasks_file = ROOT_DIR / "src" / "obfuscation_deobfuscation_crew" / "config" / "tasks.yaml"

    inputs = {
        'code': code,
        'obfuscation_techniques': techniques,
        'file_path': file_path,
        'extension': extension,
    }

    try:
        crew = ObfuscationDeobfuscationCrew(tasks_path=str(tasks_file),extension=extension)
        result = crew.crew().kickoff(inputs=inputs)
        print("Crew execution result:", result)

        if extension == "py":
            python_output_path = OUTPUT_DIR / config["PYTHON_OUTPUT_FILE_PATH"]
            if python_output_path.exists():
                remove_first_and_last_line(str(python_output_path))
            else:
                print(f"[!] Warning: {python_output_path} does not exist. Skipping remove_first_and_last_line.")

        copy_outputs(extension=f".{extension}")

    except Exception as e:
        raise Exception(f"An error occurred while running the crew: {e}")

def train():
    inputs = {"topic": "AI LLMs"}
    try:
        ObfuscationDeobfuscationCrew().crew().train(n_iterations=int(sys.argv[2]), filename=sys.argv[3], inputs=inputs)
    except Exception as e:
        raise Exception(f"An error occurred while training the crew: {e}")

def replay():
    try:
        ObfuscationDeobfuscationCrew().crew().replay(task_id=sys.argv[2])
    except Exception as e:
        raise Exception(f"An error occurred while replaying the crew: {e}")

def test():
    inputs = {
        "topic": "AI LLMs",
        "current_year": str(datetime.now().year)
    }
    try:
        ObfuscationDeobfuscationCrew().crew().test(n_iterations=int(sys.argv[2]), openai_model_name=sys.argv[3], inputs=inputs)
    except Exception as e:
        raise Exception(f"An error occurred while testing the crew: {e}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python script.py [run|train|replay|test] [args...]")
        sys.exit(1)

    command = sys.argv[1].lower()

    if command == "run":
        run()
    elif command == "train":
        train()
    elif command == "replay":
        replay()
    elif command == "test":
        test()
    else:
        print(f"Unknown command: {command}")
        sys.exit(1)
