import socket
import struct
import ssl
import threading
from nacl.public import PrivateKey, PublicKey, Box

# Setup TLS 1.3 Client Context
context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
context.minimum_version = ssl.TLSVersion.TLSv1_3
context.load_verify_locations(cafile="ca.crt")
context.check_hostname = False

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

def listen_for_messages(client_sock, box, peer_pub_key):
    try:
        while True:
            ciphertext = recv_msg(client_sock)
            if not ciphertext:
                break
            try:
                # Decrypt incoming application-layer payload using NaCl box
                decrypted_msg = box.decrypt(ciphertext)
                print(f"\n[E2E Decrypted Inbox]: {decrypted_msg.decode('utf-8')}")
            except Exception as e:
                print(f"\n[-] Decryption failed: {e}")
    except Exception:
        print("\n[-] Connection closed by server.")

def run_e2e_client():
    # 1. Generate local E2E Keypair (X25519)
    my_private_key = PrivateKey.generate()
    my_public_key = my_private_key.public_key

    # 2. Connect via TLS 1.3 to Relay
    raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client = context.wrap_socket(raw_sock, server_hostname="127.0.0.1")
    
    print("[*] Connecting to relay server via TLS 1.3...")
    client.connect(('127.0.0.1', 8443))
    print("[+] Connected to relay via TLS 1.3!")

    # 3. Protocol handshake: Send our public key to server, receive peer's public key
    client.sendall(bytes(my_public_key))
    print("[*] Sent E2E public key to relay. Waiting for peer...")
    
    peer_pub_bytes = client.recv(32) # X25519 public keys are 32 bytes
    peer_pub_key = PublicKey(peer_pub_bytes)
    
    # Compute fingerprint for verification display
    fingerprint = peer_pub_key.encode().hex()[:16]
    print(f"[+] Established E2E session with peer! Fingerprint: {fingerprint}")

    # Create NaCl Box for secure messaging
    box = Box(my_private_key, peer_pub_key)

    # Start background thread to listen for incoming encrypted messages
    threading.Thread(target=listen_for_messages, args=(client, box, peer_pub_key), daemon=True).start()

    # 4. Interactive chat loop
    print("\nType your message and press Enter to send (E2E Encrypted):")
    try:
        while True:
            plaintext = input()
            if not plaintext:
                continue
            
            # Encrypt payload using PyNaCl (handles nonce generation automatically)
            ciphertext = box.encrypt(plaintext.encode('utf-8'))
            
            # Send ciphertext through TLS tunnel via length-prefixed framing
            send_msg(client, ciphertext)
    except KeyboardInterrupt:
        print("\n[!] Disconnecting...")
    finally:
        client.close()

if __name__ == "__main__":
    run_e2e_client()