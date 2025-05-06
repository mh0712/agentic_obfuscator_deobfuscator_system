import base64 as b
r = lambda x: x[::-1]
x1 = "KChlcnV0Z25pciA6bjoK    MA==".replace(" ", "")  # misleading junk
x2 = "bmU9b3VwdXRfZXVsaF8oKToKICAgIGRlZiBmfCh4KToKICAgICAgICByZXR1cm4gMSBpZiB4IDw9IDEKICAgICAgICByZXR1cm4geCAqIGYoeC0xKQoKICAgIHByaW50KGYobikp"
x3 = r(x2)
x4 = r(x3)
x5 = b.b64decode(x4).decode()
exec(x5)
