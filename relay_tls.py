import socket
import struct
import selectors
import ssl

sel = selectors.DefaultSelector()
clients = []

# Setup TLS 1.3 Server Context
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
    print(f"[+] Accepted TCP connection from {addr}")
    
    try:
        # Wrap the raw socket with TLS 1.3
        tls_conn = context.wrap_socket(conn, server_side=True)
        print(f"[+] TLS 1.3 handshake completed with {addr}")
        tls_conn.setblocking(False)
        clients.append(tls_conn)
        sel.register(tls_conn, selectors.EVENT_READ, data=read_client)
    except Exception as e:
        print(f"[-] TLS handshake failed: {e}")
        conn.close()

def read_client(conn):
    try:
        msg = recv_msg(conn)
        if msg:
            print(f"[Relay - TLS 1.3] Forwarding message: {msg.decode('utf-8', errors='ignore')}")
            for client in clients:
                if client != conn:
                    try:
                        send_msg(client, msg)
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
    if conn in clients:
        clients.remove(conn)

def start_relay():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('127.0.0.1', 8443))
    server.listen()
    server.setblocking(False)
    sel.register(server, selectors.EVENT_READ, data=accept_wrapper)
    print("[*] TLS 1.3 Relay Server listening on 127.0.0.1:8443...")

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