import ast
import base64
import hashlib
import marshal
import os
import random
import sys
import traceback
import zlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

def build_loader(encrypted_data, aes_key, iv):
        return f"""
import sys
import os
import base64
import hashlib
import marshal
import zlib
import traceback
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

def _anti_debug():
    if sys.gettrace() or (os.name == 'nt' and __import__('ctypes').windll.kernel32.IsDebuggerPresent()):
        sys.exit(1)
_anti_debug()

_KEY = {aes_key!r}
_IV = {iv!r}

def _decrypt_str(data):
    try:
        cipher = AES.new(_KEY, AES.MODE_CBC, _IV)
        return unpad(cipher.decrypt(data), 16).decode()
    except:
        return ""

def _main():
    try:
        _encrypted = {encrypted_data!r}
        
        # Decryption steps
        cipher = AES.new(_KEY, AES.MODE_CBC, _IV)
        encrypted_data = base64.b85decode(_encrypted)
        decrypted_data = unpad(cipher.decrypt(encrypted_data), 16)
        decompressed_data = zlib.decompress(decrypted_data)
        
        exec(marshal.loads(decompressed_data), {{
            **globals(),
            '__name__': '__main__',
            '__builtins__': __builtins__,
            '_decrypt_str': _decrypt_str
        }})
    except Exception as e:
        print("Execution failed:")
        traceback.print_exc()
        sys.exit(1)

if __name__ == '__main__':
    _main()
        """
        
def obfuscate(code):
        transformed = marshal.dumps(compile(code, "<string>", "exec"))
        aes_key = os.urandom(16)
        iv = os.urandom(16)
        compressed = zlib.compress(transformed, level=9)
        cipher = AES.new(aes_key, AES.MODE_CBC,iv)
        encrypted = base64.b85encode(cipher.encrypt(pad(compressed, 16))).decode()
        
        obfuscated_code = (build_loader(encrypted, aes_key, iv))
            
        print(f"[SUCCESS] Obfuscated with key: {aes_key.hex()}")
        
        return obfuscated_code
        

if __name__ == "__main__":
    code = """
def greet(name):
    print(f"Hello, {name}!")
    
def add(a, b):
    return a + b
    
def complex_function(x):
    result = 0
    for i in range(1000):
        result += (x * i) / (i + 1)
    return result

if __name__ == "__main__":
    name = "John"
    greet(name)
    sum_result = add(5, 10)
    print(f"Sum: {sum_result}")
    complex_result = complex_function(42)
    print(f"Complex Result: {complex_result}")
"""

    obfuscate(code)
        
