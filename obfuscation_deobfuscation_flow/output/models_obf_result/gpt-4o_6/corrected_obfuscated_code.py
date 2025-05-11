```python
import base64

def f1(_0x8274):
    """Decode and greet user"""
    _0x1a9f = base64.b64decode(_0x8274).decode('utf-8')
    print(f"Hello, {_0x1a9f}!")

def f2(_0x3175, _0x2543):
    """Add two numbers"""
    return _0x3175 + _0x2543

def f3(_0x1845):
    """
    Simulate a complex operation
    """
    _0x5e92 = 0
    for _0x2bd1 in range(1000):
        _0x5e92 += (_0x1845 * _0x2bd1) / (_0x2bd1 + 1)
    return _0x5e92

# Main execution
if __name__ == "__main__":
    _0xa2dc = "Sm9obg=="  # Base64 encoded "John"
    f1(_0xa2dc)
    _0x3b754 = f2(5, 10)
    print(f"The sum of 5 and 10 is: {_0x3b754}")
    _0x5a93f = f3(42)
    print(f"Complex function result: {_0x5a93f}")
```