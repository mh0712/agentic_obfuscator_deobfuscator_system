import base64
def zzz(x): return base64.b64decode(x).decode()
print(zzz("SGVsbG8gd29ybGQ="))  # "Hello world"
