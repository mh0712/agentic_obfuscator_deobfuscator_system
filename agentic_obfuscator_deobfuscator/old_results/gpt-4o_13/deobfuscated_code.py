import base64

def reverse_string(string):
    return string[::-1]

def execute_code(code):
    return eval(code)

def always_true_predicate(expression):
    return int(expression) == 1

decoded_function_code = reverse_string("def n(n, fed): return n(n * 2)")

encoded_string = base64.b64encode(decoded_function_code.encode()).decode()
reversed_encoded_string = reverse_string(encoded_string)
decoded_string = reverse_string(reversed_encoded_string)
function_code = base64.b64decode(decoded_string).decode()

if always_true_predicate("1"):
    execute_code(function_code)
