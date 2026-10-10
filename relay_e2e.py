import socket
import struct
import selectors
import ssl

sel = selectors.DefaultSelector()
clients = []

context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.minimum_version = ssl.TLSVersion.TLSv1_3
context.load_cert_chain(certfile="server.crt", keyfile="server.key")

def send_msg(sock, message_bytes):
    length_header = struct.pack('!I', len(message_bytes))
    sock.sendall(length_header + message_bytes)

def recv_msg(sock):
    raw_length = sock.recv(4)
    if not raw_length:
        return None
    msg_length = struct.unpack('!I', raw_length)[0]
    
    data = bytearray()
    while len(data) < msg_length:
        packet = sock.recv(msg_length - len(data))
        if not packet:
            return None
        data.extend(packet)
    return bytes(data)

def accept_wrapper(server_sock):
    conn, addr = server_sock.accept()
    print(f"[+] Accepted connection from {addr}")
    try:
        tls_conn = context.wrap_socket(conn, server_side=True)
        print(f"[+] TLS 1.3 handshake completed with {addr}")
        
        # Handle initial 32-byte E2E public key exchange
        pub_key = tls_conn.recv(32)
        print(f"[Relay] Received E2E public key from {addr}")
        
        # If a peer is already waiting, exchange keys between them
        for other_conn, other_pub, _ in clients:
            # Send other's key to new client
            tls_conn.sendall(other_pub)
            # Send new client's key to other client
            other_conn.sendall(pub_key)

        tls_conn.setblocking(False)
        clients.append((tls_conn, pub_key, addr))
        sel.register(tls_conn, selectors.EVENT_READ, data=read_client)
    except Exception as e:
        print(f"[-] Error during handshake/key exchange: {e}")
        conn.close()

def read_client(conn_tuple_obj):
    # Find client connection socket from our list
    conn = conn_tuple_obj
    try:
        ciphertext = recv_msg(conn)
        if ciphertext:
            print(f"[Relay - BLIND] Forwarding E2E ciphertext ({len(ciphertext)} bytes). Relay cannot read contents!")
            for client_conn, _, _ in clients:
                if client_conn != conn:
                    try:
                        send_msg(client_conn, ciphertext)
                    except:
                        pass
        else:
            disconnect_client(conn)
    except ConnectionResetError:
        disconnect_client(conn)

def disconnect_client(conn):
    print("[-] Client disconnected")
    sel.unregister(conn)
    conn.close()
    global clients
    clients = [c for c in clients if c[0] != conn]

def start_relay():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('127.0.0.1', 8443))
    server.listen()
    server.setblocking(False)
    sel.register(server, selectors.EVENT_READ, data=accept_wrapper)
    print("[*] E2E-Aware TLS Relay Server listening on 127.0.0.1:8443...")

    try:
        while True:
            events = sel.select(timeout=None)
            for key, mask in events:
                callback = key.data
                callback(key.fileobj)
    except KeyboardInterrupt:
        print("\n[!] Shutting down relay server.")
    finally:
        sel.close()

if __name__ == "__main__":
    start_relay()