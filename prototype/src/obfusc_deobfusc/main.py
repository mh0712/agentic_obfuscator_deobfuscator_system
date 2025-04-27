#!/usr/bin/env python
# src/latest_ai_development/main.py
import sys
from crew import ObfuscationCrew,load_yaml_config

def run():
  """
  Run the crew.
  """
  inputs = {
    'file_path': 'C:\Users\celin\Desktop\usj\FYP\agentic_obfuscator_deobfuscator_system\samples\hello.py'
  }
  agents_config = load_yaml_config('src/obfusc_deobfusc/config/agents.yaml')
  tasks_config = load_yaml_config('src/obfusc_deobfusc/config/tasks.yaml')
  techniques_config = load_yaml_config('src/obfusc_deobfusc/config/obfuscation_techniques.yaml')
  
  ObfuscationCrew(agents_config=agents_config,tasks_config=tasks_config,techniques_config=techniques_config).crew().kickoff(inputs=inputs)