#!/usr/bin/env python2

from __future__ import print_function
from ctypes import cdll, Structure, POINTER, c_char, c_char_p, c_uint32, cast

rp = cdll.LoadLibrary('./target/debug/librusterpassword_capi.so')
class SecStr(Structure): pass
rp.rusterpassword_gen_master_key.restype = POINTER(SecStr)
rp.rusterpassword_gen_site_seed.restype = POINTER(SecStr)
rp.rusterpassword_gen_site_password.restype = POINTER(c_char)
# c_char_p here would change the address!!! WTF Python

mkey = rp.rusterpassword_gen_master_key("Correct Horse Battery Staple", "Cosima Niehaus")
sseed = rp.rusterpassword_gen_site_seed(mkey, "twitter.com", 5)
passwd = rp.rusterpassword_gen_site_password(sseed, 50)
passwd_s = cast(passwd, c_char_p).value
print(passwd_s)
assert passwd_s == "Kiwe2^BecuRodw"
rp.rusterpassword_free_site_password(passwd)
rp.rusterpassword_free_site_seed(sseed)
rp.rusterpassword_free_master_key(mkey)
