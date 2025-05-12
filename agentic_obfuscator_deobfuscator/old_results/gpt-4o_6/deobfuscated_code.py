import base64

# Reverse string
def reverse_string(s):
    return s[::-1]

# Evaluate a string as Python code
def eval_code(s):
    return eval(s)

# Opaque predicate always returns True
def opaque_predicate(x):
    return int(x) if 42 >> 1 == 21 else 0  # simplified to True branch only 

# Reverse the hardcoded base64 encoded function
decoded_function = reverse_string("d esab46edoc(100)n ,deffo d))n nrett)n n2*(")

# Encode the reversed function in Base64 and reverse it
encoded = base64.b64encode(decoded_function.encode()).decode()
reversed_encoded = reverse_string(encoded)

# Decode the reversed, encoded string back to the source
decoded_source = base64.b64decode(reverse_string(reversed_encoded)).decode()

# If the opaque predicate is True, eval the decoded source
if opaque_predicate("1"):
    eval_code(decoded_source)
