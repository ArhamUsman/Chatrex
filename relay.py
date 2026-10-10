import socket
import struct
import selectors

sel = selectors.DefaultSelector()
clients = []

def send_msg(sock, message_bytes):
    """Prefixes message with a 4-byte big-endian length header and sends."""
    length_header = struct.pack('!I', len(message_bytes))
    sock.sendall(length_header + message_bytes)

def recv_msg(sock):
    """Reads the 4-byte length header, then reads the exact payload size."""
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
    conn.setblocking(False)
    clients.append(conn)
    sel.register(conn, selectors.EVENT_READ, data=read_client)

def read_client(conn):
    try:
        msg = recv_msg(conn)
        if msg:
            print(f"[Relay] Forwarding message: {msg.decode('utf-8', errors='ignore')}")
            # Broadcast to all other connected clients
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
    print("[*] TCP Relay Server listening on 127.0.0.1:8443...")

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