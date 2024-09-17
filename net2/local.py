import socket
import struct

def recvall(sock, n):
    # Helper function to receive exactly n bytes from the socket
    data = b''
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            return None  # Connection closed
        data += packet
    return data

# Connect to the server
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('127.0.0.1', 2997))

# Receive exactly 16 bytes (4 unsigned integers)
data = recvall(s, 16)
if data is None:
    print("Failed to receive data")
else:
    quad = struct.unpack('4I', data)
    print("Received numbers:",quad)

    # Calculate the sum of the received numbers
    result = sum(quad) % (2**32)

    # Send the result back to the server as an unsigned int
    s.sendall(struct.pack('I', result))

    print(s.recv(1024))

# Close the connection
s.close()
