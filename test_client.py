import socket
import struct

def send_msg(sock, message_bytes):
    length_header = struct.pack('!I', len(message_bytes))
    sock.sendall(length_header + message_bytes)

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(('127.0.0.1', 8443))
print("[+] Connected to relay server!")

# Send a test message
msg = b"Hello from Arham's client!"
send_msg(client, msg)
print("[+] Message sent!")
client.close()