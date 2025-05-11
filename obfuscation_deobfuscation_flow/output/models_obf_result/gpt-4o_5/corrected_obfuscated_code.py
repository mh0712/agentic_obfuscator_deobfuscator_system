
import base64

def z(x):  # complex_function obfuscated
    Y, a = 0, range(1000)
    for b in a:
        Y += (x * b) / (b + 1)
    return Y

def a2B(name):  # greet obfuscated
    Z = base64.b64decode(b"SGVsbG8sICVzIQ==").decode()  # Encoded greeting format
    print(Z % name)

def B2(x, y):  # add obfuscated
    return x + y

N = base64.b64decode(b"Sm9obg==").decode()  # Encoded "John"
if __name__ == "__main__":
    a2B(N)
    Y = B2(5, 10)
    print(base64.b64decode(b"VGhlIHN1bSBvZiUgYW5kICUgaXM6ICVz").decode() % (5, 10, Y))
    Z = z(42)
    print(base64.b64decode(b"Q29tcGxleCBmdW5jdGlvbiByZXN1bHQ6ICVz").decode() % Z)
