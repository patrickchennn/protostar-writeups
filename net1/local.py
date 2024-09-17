import socket
import struct
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
ADDR = "127.0.0.1"
PORT = 2998
s.connect((ADDR,PORT))

n = s.recv(4)
print(n)
print(repr(n))
print(n.encode('hex'))

N = struct.unpack("I",n)
print(N)
s.send(str(N[0]))
print(s.recv(1024))