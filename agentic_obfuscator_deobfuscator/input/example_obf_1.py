_ = lambda f: (lambda x: f(lambda *a: x(x)(*a)))(lambda x: f(lambda *a: x(x)(*a)))
__ = lambda n: _(
    lambda f: lambda a, b: [a] + f(b, a + b) if a < n else []
)
print('\n'.join(map(str, __(100))))
