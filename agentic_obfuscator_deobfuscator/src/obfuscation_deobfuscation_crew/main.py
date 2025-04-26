#!/usr/bin/env python
import sys
import json
import warnings
from datetime import datetime
from obfuscation_deobfuscation_crew.crew import ObfuscationDeobfuscationCrew
from models_obf_result.controller import copy_outputs
from obfuscation_deobfuscation_crew.config import config
from obfuscation_deobfuscation_crew.utils.utils import remove_first_and_last_line


warnings.filterwarnings("ignore", category=SyntaxWarning, module="pysbd")

def run():
    """
    Run the crew for the obfuscation task.
    """
    file_path = sys.argv[2] if len(sys.argv) > 2 else 'C:\\Users\\celin\\Desktop\\usj\\FYP\\crew_agents\\obfuscation_deobfuscation_crew\\example.py'
    with open(file_path, 'r', encoding='utf-8') as f:
        code = f.read()

    # Load obfuscation techniques from JSON
    with open('src/obfuscation_deobfuscation_crew/config/obfuscation_techniques.json', 'r', encoding='utf-8') as f:
        techniques = json.load(f)

    inputs = {
        'code': code,
        'obfuscation_techniques': techniques,
        'file_path': file_path,
    }

    try:
        result = ObfuscationDeobfuscationCrew().crew().kickoff(inputs=inputs)
        print("Crew execution result:", result)
        # Example usage
        remove_first_and_last_line(config["PYTHON_OUTPUT_FILE_PATH"])
        copy_outputs()

    except Exception as e:
        raise Exception(f"An error occurred while running the crew: {e}")

def train():
    """
    Train the crew for a given number of iterations.
    """
    inputs = {"topic": "AI LLMs"}
    try:
        ObfuscationDeobfuscationCrew().crew().train(n_iterations=int(sys.argv[2]), filename=sys.argv[3], inputs=inputs)
    except Exception as e:
        raise Exception(f"An error occurred while training the crew: {e}")

def replay():
    """
    Replay the crew execution from a specific task.
    """
    try:
        ObfuscationDeobfuscationCrew().crew().replay(task_id=sys.argv[2])
    except Exception as e:
        raise Exception(f"An error occurred while replaying the crew: {e}")

def test():
    """
    Test the crew execution and returns the results.
    """
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
