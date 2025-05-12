_ = lambda f: (lambda x: x(x))(lambda y: f(lambda *a: y(y)(*a)))
fact = _(lambda f: lambda n: 1 if n < 2 else n * f(n - 1))
exec(''.join([chr(c) for c in [112, 114, 105, 110, 116, 40, 39, 70, 97, 99, 116, 111, 114, 105, 97, 108, 58, 39, 44, 32, 115, 116, 114, 40, 102, 97, 99, 116, 40, 53, 41, 41, 41]]))
