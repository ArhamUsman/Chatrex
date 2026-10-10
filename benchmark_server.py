import socket
import struct
import ssl
from nacl.public import PrivateKey, PublicKey, Box  # <--- Added PublicKey here

context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.minimum_version = ssl.TLSVersion.TLSv1_3
context.load_cert_chain(certfile="server.crt", keyfile="server.key")

def recv_exact(sock, num_bytes):
    data = bytearray()
    while len(data) < num_bytes:
        packet = sock.recv(num_bytes - len(data))
        if not packet:
            return None
        data.extend(packet)
    return bytes(data)

def recv_msg(sock):
    raw_length = recv_exact(sock, 4)
    if not raw_length:
        return None
    msg_length = struct.unpack('!I', raw_length)[0]
    return recv_exact(sock, msg_length)

def send_msg(sock, message_bytes):
    length_header = struct.pack('!I', len(message_bytes))
    sock.sendall(length_header + message_bytes)

def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('10.0.3.10', 8443))
    server.listen(5)
    print("[*] Robust Multi-Mode Echo Server listening on 10.0.3.10:8443...")

    try:
        while True:
            conn, addr = server.accept()
            active_conn = None
            try:
                mode_flag = conn.recv(1)
                if not mode_flag:
                    conn.close()
                    continue
                
                mode = mode_flag[0]

                if mode in [1, 2]:
                    active_conn = context.wrap_socket(conn, server_side=True)
                else:
                    active_conn = conn

                if mode == 2:
                    server_priv = PrivateKey.generate()
                    server_pub = server_priv.public_key
                    
                    client_pub_bytes = recv_exact(active_conn, 32)
                    if not client_pub_bytes or len(client_pub_bytes) != 32:
                        print(f"[-] E2E handshake failed: invalid public key received.")
                        conn.close()
                        continue
                    
                    active_conn.sendall(bytes(server_pub))
                    
                    # FIX: Use PublicKey instead of PrivateKey for the received public key bytes
                    client_pub = PublicKey(client_pub_bytes) 
                    box = Box(server_priv, client_pub)

                    while True:
                        ciphertext = recv_msg(active_conn)
                        if not ciphertext:
                            break
                        send_msg(active_conn, ciphertext)
                else:
                    while True:
                        msg = recv_msg(active_conn)
                        if not msg:
                            break
                        send_msg(active_conn, msg)

            except Exception as e:
                print(f"[-] Server error with {addr}: {e}")
            finally:
                conn.close()
    except KeyboardInterrupt:
        print("\n[!] Shutting down server.")
    finally:
        server.close()

if __name__ == "__main__":
    start_server()