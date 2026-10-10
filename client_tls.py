import socket
import struct
import ssl

# Setup TLS 1.3 Client Context
context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
context.minimum_version = ssl.TLSVersion.TLSv1_3
context.load_verify_locations(cafile="ca.crt")
# Since our cert has SAN IP:127.0.0.1, we ensure hostname/IP validation matches
context.check_hostname = False # For local IP testing with custom CA

def send_msg(sock, message_bytes):
    length_header = struct.pack('!I', len(message_bytes))
    sock.sendall(length_header + message_bytes)

def run_client():
    # 1. Create standard TCP socket
    raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    # 2. Wrap socket with TLS 1.3
    client = context.wrap_socket(raw_sock, server_hostname="127.0.0.1")
    
    print("[*] Connecting to relay server via TLS 1.3...")
    client.connect(('127.0.0.1', 8443))
    print("[+] Connected and TLS handshake successful!")

    # 3. Send encrypted message
    msg = b"Hello through a secure TLS 1.3 tunnel!"
    send_msg(client, msg)
    print("[+] Encrypted message sent!")
    client.close()

if __name__ == "__main__":
    run_client()