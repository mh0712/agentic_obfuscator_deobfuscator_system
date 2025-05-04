# Script for Ghidra (Python/Jython)
# Extracts enriched function metadata for LLM input and filters out small/useless functions
# Filters functions called by external functions to reduce irrelevant data

#@author
#@category Functions
#@keybinding
#@menupath
#@toolbar

import json
import os
from collections import defaultdict
import random

from ghidra.program.model.symbol import RefType
from ghidra.program.model.listing import Function
from ghidra.util.task import ConsoleTaskMonitor

def guess_role(func_name):
    """
    Naive heuristics to guess role based on function names
    """
    name = func_name.lower()
    if "init" in name:
        return "initializer"
    elif "main" in name:
        return "main_logic"
    elif "exit" in name or "cleanup" in name:
        return "terminator"
    elif "lock" in name or "mutex" in name:
        return "synchronization"
    elif "printf" in name or "print" in name or "format" in name:
        return "formatting"
    else:
        return "utility"

def get_function_data(func, call_graph, reverse_call_graph):
    func_data = {
        "name": func.getName(),
        "address": str(func.getEntryPoint()),
        "return_type": func.getReturnType().getDisplayName(),
        "parameters": [],
        "size": func.getBody().getNumAddresses(),
        "instruction_count": 0,
        "calls": [],
        "called_by": [],
        "is_leaf": True,
        "function_type": "internal",
        "is_imported": False,
        "call_count": 0,
        "possible_role": guess_role(func.getName())
    }

    # Parameters
    for param in func.getParameters():
        param_info = {
            "name": param.getName(),
            "datatype": param.getDataType().getDisplayName()
        }
        func_data["parameters"].append(param_info)

    # Analyze instructions
    instructions = currentProgram.getListing().getInstructions(func.getBody(), True)
    instruction_counter = 0
    for instr in instructions:
        instruction_counter += 1
        for ref in instr.getReferencesFrom():
            if ref.getReferenceType().isCall():
                called_func = getFunctionAt(ref.getToAddress())
                if called_func:
                    func_data["calls"].append(called_func.getName())
                    func_data["is_leaf"] = False
    func_data["instruction_count"] = instruction_counter

    # Call graph info
    if func.getName() in reverse_call_graph:
        func_data["called_by"] = list(reverse_call_graph[func.getName()])
        func_data["call_count"] = len(reverse_call_graph[func.getName()])

    # Imported / External
    if func.isExternal():
        func_data["function_type"] = "external"
        func_data["is_imported"] = True

    return func_data

def build_call_graph(functions):
    call_graph = defaultdict(set)
    reverse_call_graph = defaultdict(set)

    for func in functions:
        if func.isExternal():
            continue

        instructions = currentProgram.getListing().getInstructions(func.getBody(), True)
        for instr in instructions:
            for ref in instr.getReferencesFrom():
                if ref.getReferenceType().isCall():
                    called_func = getFunctionAt(ref.getToAddress())
                    if called_func:
                        call_graph[func.getName()].add(called_func.getName())
                        reverse_call_graph[called_func.getName()].add(func.getName())

    return call_graph, reverse_call_graph

def traverse_call_graph(entry_func):
    visited = set()
    to_visit = [entry_func]

    while to_visit:
        func = to_visit.pop()
        if func in visited:
            continue
        visited.add(func)
        called_funcs = find_called_functions(func)
        to_visit.extend(called_funcs - visited)

    return visited

def find_called_functions(func):
    called_funcs = set()
    instructions = currentProgram.getListing().getInstructions(func.getBody(), True)

    for instr in instructions:
        for ref in instr.getReferencesFrom():
            if ref.getReferenceType().isCall():
                called_func = getFunctionAt(ref.getToAddress())
                if called_func:
                    called_funcs.add(called_func)
    return called_funcs

def get_entry_function():
    symbol_table = currentProgram.getSymbolTable()
    possible_names = ["_start", "entry", "main"]

    for name in possible_names:
        symbols = symbol_table.getSymbols(name)
        if symbols.hasNext():
            symbol = symbols.next()
            func = getFunctionAt(symbol.getAddress())
            if func:
                print("[+] Found entry function:", name)
                return func

    # fallback: image base
    image_base = currentProgram.getImageBase()
    func = getFunctionAt(image_base)
    if func:
        print("[+] Using image base as entry:", func.getName())
        return func

    print("[-] No entry function found.")
    return None

def save_as_json(data, filename):
    filepath = os.path.join(os.path.expanduser("~"), filename)
    with open(filepath, 'w') as f:
        json.dump(data, f, indent=4)
    print("[+] Data saved to {}".format(filepath))

def filter_small_functions(func):
    """
    Filter out small functions based on some thresholds:
    - Ignore functions with very low instruction count
    - Ignore `thunk` functions (wrappers)
    - Ignore `external` functions unless needed
    """
    # Ignore small functions with very few instructions
    if func.getBody().getNumAddresses() < 10:
        return True

    # Ignore functions that are just thunks (wrappers)
    if func.getName().startswith("thunk_"):
        return True

    # Skip completely external functions unless needed
    if func.isExternal():
        return True

    return False

def filter_called_by_external(func, reverse_call_graph):
    """
    Filters out functions that are only called by external functions.
    """
    called_by_external = False
    for caller in reverse_call_graph.get(func.getName(), []):
        try:
            caller_func_address = currentProgram.getAddressFactory().getAddress(caller)
            if caller_func_address is None:
                continue  # Skip invalid addresses
            caller_func = getFunctionAt(caller_func_address)
            if caller_func and caller_func.isExternal():
                called_by_external = True
                break
        except Exception as e:
            print("Error processing caller {} : {}".format(caller, e))
            continue

    if called_by_external:
        return True  # Exclude this function as it's only called by an external function
    
    return False  # Include this function if it's not called only by external functions
def filter_function_by_params(func):
    """
    Filters out functions with no parameters or a return type of 'void' that are less likely to be important.
    """
    if len(func.getParameters()) == 0 and func.getReturnType().getDisplayName() == "void":
        return True
    return False

def filter_by_size(func):
    """
    Filters out functions smaller than a certain size.
    """
    if func.getBody().getNumAddresses() < 10:  # Example threshold
        return True
    return False

import datetime

def main():
    entry_func = get_entry_function()
    if entry_func is None:
        return

    all_funcs = traverse_call_graph(entry_func)
    call_graph, reverse_call_graph = build_call_graph(all_funcs)
    results = []

    for func in all_funcs:
        # Apply filters
        if (filter_small_functions(func) or 
            filter_called_by_external(func, reverse_call_graph) or
            filter_function_by_params(func) or
            filter_by_size(func)):
            continue

        data = get_function_data(func, call_graph, reverse_call_graph)
        results.append(data)

    #Generate unique filename
    i = random.randint(0, 100000)
    output_file = "C:\\Users\\celin\\Desktop\\usj\\FYP\\agentic_obfuscator_deobfuscator_system\\agentic_obfuscator_deobfuscator\\src\\obfuscation_deobfuscation_crew\\tools\\ghidra_output\\filtered_functions_obfuscated_{}.json".format(i)
    
    # Save to JSON
    with open(output_file, "w") as json_file:
        json.dump(results, json_file, indent=4)

    print("[+] Analysis saved to {}".format(output_file))

main()
