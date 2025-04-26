from src.obfuscation_deobfuscation_crew.tools.python_tools import obfuscate_py
from src.obfuscation_deobfuscation_crew.tools.javascript_tools import obfuscate_js


def obfuscate(code: str, language: str) -> str:
    """
    Obfuscate the given code based on its language.
    
    Args:
        code (str): The code to be obfuscated.
        language (str): The programming language ('python' or 'javascript').
    
    Returns:
        str: The obfuscated code.
    """
    if language.lower() == "python":
        return obfuscate_py(code)
    elif language.lower() == "javascript":
        result = obfuscate_js(code)
        return result
    else:
        raise ValueError(f"Unsupported language: {language}")
    
if __name__ == "__main__":

    obfuscate("console.log('Hello, World!');", "javascript")

        


        
