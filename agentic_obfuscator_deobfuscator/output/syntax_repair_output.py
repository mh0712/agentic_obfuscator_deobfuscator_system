```python
def fibonacci(n):
    def fib_recursive(a, b):
        if a < n:
            return [a] + fib_recursive(b, a + b)
        else:
            return []

    return fib_recursive(0, 1)

print('\n'.join(map(str, fibonacci(100))))
```
This cleaned code is syntactically valid, complete, and retains the intended functionality of generating and printing Fibonacci numbers up to 100.