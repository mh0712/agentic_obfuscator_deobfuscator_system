import base64 as b

def r(x):
    return x[::-1]

x1 = 'KChlcnV0Z25pciA6bjoKMA=='.replace(' ', '')
x2 = 'ne=ouput_eulh_():\n    def f|(x):\n        return 1 if x <= 1\n        return x * f(x-1)\n\n    print(f(n))'
x3 = r(x2)
x4 = r(x3)
x5 = b.b64decode(x4).decode()
exec(x5)