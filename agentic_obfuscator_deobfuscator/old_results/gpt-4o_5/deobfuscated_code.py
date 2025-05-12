import base64

# Reverse the given string
reverse_string = lambda x: x[::-1]

# Evaluate the given string
evaluate_code = lambda x: eval(x)

# Opaque predicate: always returns 1 since the condition (42 >> 1) == 21 is true
check_condition = lambda x: int(x * True)  

# Decode and reverse the string to get actual code
actual_code = reverse_string("def(n: return(n * 2)")

# Base64 encode, reverse, and then decode to simulate extra obfuscation
encoded_string = base64.b64encode(actual_code.encode()).decode()
reverse_first = reverse_string(encoded_string)
reverse_back = reverse_string(reverse_first)
decoded_string = base64.b64decode(reverse_back).decode()

# Always true check allows evaluation
if check_condition("1"):
    evaluate_code(decoded_string)