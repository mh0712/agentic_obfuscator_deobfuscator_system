#!/usr/bin/env python
import sys
import json
import warnings
from datetime import datetime
from obfuscation_deobfuscation_crew.crew import BinaryObfuscationCrew
from models_obf_result.controller import copy_outputs
from obfuscation_deobfuscation_crew.config import config
from obfuscation_deobfuscation_crew.utils.utils import remove_first_and_last_line


warnings.filterwarnings("ignore", category=SyntaxWarning, module="pysbd")

def run():
    """
    Run the crew for the obfuscation task.
    """
    

    # Load obfuscation techniques from JSON
    with open('src/obfuscation_deobfuscation_crew/config/binary_obfuscation_techniques.json', 'r', encoding='utf-8') as f:
        techniques = json.load(f)

    inputs = {
        # 'code': code,
        # 'obfuscation_techniques': techniques,
        # 'file_path': file_path,
        'binary_path': r"C:\Users\celin\Desktop\usj\FYP\agentic_obfuscator_deobfuscator_system\agentic_obfuscator_deobfuscator\test_obf.exe",
        'obfuscation_techniques': techniques,
        
    }

    try:
        result = BinaryObfuscationCrew().crew().kickoff(inputs=inputs)
        print("Crew execution result:", result)
        # Example usage
        # remove_first_and_last_line(config["PYTHON_OUTPUT_FILE_PATH"])
        # copy_outputs()

    except Exception as e:
        raise Exception(f"An error occurred while running the crew: {e}")

def train():
    """
    Train the crew for a given number of iterations.
    """
    inputs = {"topic": "AI LLMs"}
    try:
        BinaryObfuscationCrew().crew().train(n_iterations=int(sys.argv[2]), filename=sys.argv[3], inputs=inputs)
    except Exception as e:
        raise Exception(f"An error occurred while training the crew: {e}")

def replay():
    """
    Replay the crew execution from a specific task.
    """
    try:
        BinaryObfuscationCrew().crew().replay(task_id=sys.argv[2])
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
        BinaryObfuscationCrew().crew().test(n_iterations=int(sys.argv[2]), openai_model_name=sys.argv[3], inputs=inputs)
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
