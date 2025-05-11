# Final obfuscated code here
_9=print
_M=range
_ab=__import__
class _C1:
    def __init__(_a):
        _a._b=_E12
    @staticmethod
    def _Z19(name):
        _9(f"Hello, {name}!")
class _C2:
     _K98=staticmethod(lambda a,b:a+b) 
class _C3:
    @_ab('functools').lru_cache(None)
    def _E12(x):
        _U=0
        for _R in _M(1000):
            _U+=(_R*x)/(_R+1)
        return _U
if __name__=="__main__":
    _l=_C1()
    _l._Z19("John")
    _68=_C2._K98(5,10)
    _9(f"The sum of 5 and 10 is: {_68}")
    _a0=_l._b(42)
    _9(f"Complex function result: {_a0}")
