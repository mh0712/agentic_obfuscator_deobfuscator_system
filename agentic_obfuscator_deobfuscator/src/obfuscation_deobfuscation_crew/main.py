#!/usr/bin/env python
import os
import sys
import json
import string
import warnings
from pathlib import Path
from datetime import datetime
from obfuscation_deobfuscation_crew.crew import ObfuscationDeobfuscationCrew
from models_obf_result.controller import copy_clean_outputs, get_file_extension


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

def choose_operation():
    operations = ["obfuscate", "deobfuscate"]
    print("\n[+] Available operations:")
    for idx, operation in enumerate(operations):
        print(f"[{idx}] {operation}")

    while True:
        choice = input("\nChoose an operation (0/1): ").strip()
        if choice.isdigit() and int(choice) < len(operations):
            selected_operation = operations[int(choice)]
            print(f"[+] Selected operation: {selected_operation}")
            return selected_operation
        else:
            print("[!] Invalid choice. Please select a valid number.")


def run():
    file_path = (
        sys.argv[2]
        if len(sys.argv) > 2
        else choose_input_file()
    )
    
    
    operation = (
        sys.argv[3]
        if len(sys.argv) > 3
        else choose_operation()
    )


    # Dynamically detect extension
    extension = get_file_extension(file_path)
    print(f"[+] Detected file extension: {extension}")

    with open(file_path, "r", encoding="utf-8") as f:
        code = f.read()

    if operation == "obfuscate":
        techniques_path = ROOT_DIR / "src" / "obfuscation_deobfuscation_crew" / "config" / "obfuscation_techniques.json"
    elif operation == "deobfuscate":
        techniques_path = ROOT_DIR / "src" / "obfuscation_deobfuscation_crew" / "config" / "deobfuscation_techniques.json" 

    if not techniques_path.exists():
        print(f"[!] Warning: {techniques_path} does not exist. Please check the path.")
        sys.exit(1)
    
    with open(techniques_path, "r", encoding="utf-8") as f:
        techniques = json.load(f)

    tasks_file = ROOT_DIR / "src" / "obfuscation_deobfuscation_crew" / "config" / "tasks.yaml"

    inputs = {
        'code': code,
        'file_path': file_path,
        'extension': extension,
        'operation': operation,
    }
    
    if operation == "obfuscate":
        inputs['obfuscation_techniques'] = techniques
    elif operation == "deobfuscate":
        inputs['deobfuscation_techniques'] = techniques
    
    print(f"[+] Inputs for crew: {inputs}")
    
 

    try:
        crew = ObfuscationDeobfuscationCrew(tasks_path=str(tasks_file),extension=extension,operation=operation)
        result = crew.crew().kickoff(inputs=inputs)
        print("Crew execution result:", result)            
        copy_clean_outputs(inputFile=file_path)
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
