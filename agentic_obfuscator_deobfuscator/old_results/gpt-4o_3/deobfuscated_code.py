def factorial(n):
    return 1 if n < 2 else n * factorial(n - 1)

print('Factorial:', factorial(5))
