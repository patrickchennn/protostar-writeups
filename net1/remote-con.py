import socket

# Connect to the server running inside VirtualBox (replace IP with the VM's IP)
VM_IP = '10.7.120.206'  # Replace with the actual IP of your VirtualBox VM or '127.0.0.1' if using port forwarding
VM_PORT = 2998  # The port your server is running on

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((VM_IP, VM_PORT))

# Receive 4 bytes (the size of an unsigned int)
data = s.recv(4)
print(data)

# Convert the received bytes to an unsigned integer
value = int.from_bytes(data, byteorder='little')
print(hex(value))  # Print the value in hexadecimal

# Send the number back as a string
s.sendall(f"{value}\n".encode())

print(s.recv(1024))

# Close the connection
s.close()
