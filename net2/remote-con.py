import socket
import struct

# Connect to the server running inside VirtualBox (replace IP with the VM's IP)
VM_IP = '10.7.120.206'  # Replace with the actual IP of your VirtualBox VM or '127.0.0.1' if using port forwarding
VM_PORT = 2997  # The port your server is running on

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((VM_IP, VM_PORT))

# Receive 4 unsigned integers (4 bytes each)
# data = s.recv(16) 

data = s.recv(4) 
data += s.recv(4) 
data += s.recv(4) 
data += s.recv(4) 

print("data=",data)


# Unpack the binary data into 4 unsigned integers
quad = struct.unpack('4I', data)
print(f"Received numbers: {quad}")

# Send the sum of the numbers back to the server
sumQuad = sum(quad)
print("sumQuad=",sumQuad)
print(f"0 <= {sumQuad} <= 4294967295=",0 <= sumQuad <= 4294967295)

s.sendall(struct.pack('I', sumQuad))

print(s.recv(1024))

# Close the connection
s.close()
