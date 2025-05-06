import base64

def decode_base64(encoded_string):
    return base64.b64decode(encoded_string).decode()

print(decode_base64("SGVsbG8gd29ybGQ="))  # "Hello world"
