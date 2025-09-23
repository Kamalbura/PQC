# ==============================================================================
# gcs_kyber_768.py
#
# GCS-Side Proxy for Post-Quantum Key Exchange using ML-KEM-768 (Kyber-768)
# REFERENCE IMPLEMENTATION - Use as template for other Kyber variants
#
# METHOD:
#   1) Perform a Kyber (ML-KEM-768) key exchange over TCP to derive a shared key.
#   2) Use AES-256-GCM with the derived key for UDP MAVLink streams.
#
# FIXES APPLIED:
# - Persistent key exchange server for multiple connections
# - Proper error handling and connection management
# - Thread synchronization with crypto initialization
# - Separate sockets for send/receive operations
# ==============================================================================

import socket
import threading
import os
import hashlib
import time
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from ip_config import *

print("[KYBER-768 GCS] Starting Key Exchange (ML-KEM-768)...")

import oqs.oqs as oqs

# Global crypto objects - initialized after key exchange
aesgcm = None
crypto_ready = threading.Event()

def _recv_exact(conn: socket.socket, n: int) -> bytes:
    data = bytearray()
    while len(data) < n:
        chunk = conn.recv(n - len(data))
        if not chunk:
            raise ConnectionError("Socket closed while receiving data")
        data.extend(chunk)
    return bytes(data)

def _recv_with_len(conn: socket.socket) -> bytes:
    n = int.from_bytes(_recv_exact(conn, 4), 'big')
    return _recv_exact(conn, n)

def _send_with_len(conn: socket.socket, data: bytes):
    conn.sendall(len(data).to_bytes(4, 'big'))
    conn.sendall(data)

def handle_key_exchange():
    """Handle key exchange with persistent server"""
    global aesgcm, crypto_ready
    
    kem = oqs.KeyEncapsulation("ML-KEM-768")
    gcs_public_key = kem.generate_keypair()
    
    ex_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ex_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        ex_sock.bind((GCS_HOST, PORT_KEY_EXCHANGE))
    except OSError as e:
        print(f"[KYBER-768 GCS] bind failed on {GCS_HOST}:{PORT_KEY_EXCHANGE} -> {e}; falling back to 0.0.0.0")
        ex_sock.bind(("0.0.0.0", PORT_KEY_EXCHANGE))
    ex_sock.listen(1)
    print(f"[KYBER-768 GCS] Waiting on {GCS_HOST}:{PORT_KEY_EXCHANGE}...")
    
    # Accept first successful connection
    while True:
        try:
            conn, addr = ex_sock.accept()
            conn.settimeout(10.0)  # 10 second timeout for handshake
            print(f"[KYBER-768 GCS] Connection from {addr}")
            
            _send_with_len(conn, gcs_public_key)
            ciphertext = _recv_with_len(conn)
            ss = kem.decap_secret(ciphertext)
            AES_KEY = hashlib.sha256(ss).digest()
            conn.close()
            
            # Initialize crypto
            aesgcm = AESGCM(AES_KEY)
            crypto_ready.set()  # Signal threads that crypto is ready
            print("✅ [KYBER-768 GCS] Shared key established")
            break
            
        except Exception as e:
            print(f"[KYBER-768 GCS] Handshake failed for {addr}: {e}")
            try:
                conn.close()
            except:
                pass
            continue
    
    ex_sock.close()

# Perform key exchange before starting threads
handle_key_exchange()


def encrypt_message(plaintext: bytes) -> bytes:
    """Encrypt message using AES-256-GCM"""
    if not crypto_ready.is_set():
        raise RuntimeError("Crypto not initialized")
    nonce = os.urandom(NONCE_IV_SIZE)
    ct = aesgcm.encrypt(nonce, plaintext, None)
    return nonce + ct


def decrypt_message(encrypted_message: bytes):
    """Decrypt message using AES-256-GCM"""
    if not crypto_ready.is_set():
        return None
    try:
        if len(encrypted_message) < NONCE_IV_SIZE:
            return None
        nonce = encrypted_message[:NONCE_IV_SIZE]
        ct = encrypted_message[NONCE_IV_SIZE:]
        return aesgcm.decrypt(nonce, ct, None)
    except Exception as e:
        print(f"[KYBER-768 GCS] Decryption failed: {e}")
        return None


def drone_to_gcs_thread():
    """Thread 1: Decrypt incoming telemetry from drone to GCS application"""
    # Wait for crypto to be ready
    crypto_ready.wait()
    
    # Listen for encrypted telemetry from drone
    listen_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        listen_sock.bind((GCS_HOST, PORT_GCS_LISTEN_ENCRYPTED_TLM))
    except OSError as e:
        print(f"[KYBER-768 GCS] UDP bind failed on {GCS_HOST}:{PORT_GCS_LISTEN_ENCRYPTED_TLM} -> {e}; using 0.0.0.0")
        listen_sock.bind(("0.0.0.0", PORT_GCS_LISTEN_ENCRYPTED_TLM))
    
    # Socket to forward decrypted telemetry to GCS application
    forward_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    print(f"[KYBER-768 GCS] Listening encrypted TLM on {GCS_HOST}:{PORT_GCS_LISTEN_ENCRYPTED_TLM}")
    print(f"[KYBER-768 GCS] Forwarding decrypted TLM to {GCS_HOST}:{PORT_GCS_FORWARD_DECRYPTED_TLM}")
    
    while True:
        try:
            data, addr = listen_sock.recvfrom(65535)
            pt = decrypt_message(data)
            if pt:
                forward_sock.sendto(pt, (GCS_HOST, PORT_GCS_FORWARD_DECRYPTED_TLM))
        except Exception as e:
            print(f"[KYBER-768 GCS] Telemetry thread error: {e}")
            time.sleep(0.1)


def gcs_to_drone_thread():
    """Thread 2: Encrypt outgoing commands from GCS application to drone"""
    # Wait for crypto to be ready
    crypto_ready.wait()
    
    # Listen for plaintext commands from GCS application
    listen_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        listen_sock.bind((GCS_HOST, PORT_GCS_LISTEN_PLAINTEXT_CMD))
    except OSError as e:
        print(f"[KYBER-768 GCS] UDP bind failed on {GCS_HOST}:{PORT_GCS_LISTEN_PLAINTEXT_CMD} -> {e}; using 0.0.0.0")
        listen_sock.bind(("0.0.0.0", PORT_GCS_LISTEN_PLAINTEXT_CMD))
    
    # Socket to send encrypted commands to drone
    send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    print(f"[KYBER-768 GCS] Listening plaintext CMD on {GCS_HOST}:{PORT_GCS_LISTEN_PLAINTEXT_CMD}")
    print(f"[KYBER-768 GCS] Forwarding encrypted CMD to {DRONE_HOST}:{PORT_DRONE_LISTEN_ENCRYPTED_CMD}")
    
    while True:
        try:
            data, addr = listen_sock.recvfrom(65535)
            enc = encrypt_message(data)
            send_sock.sendto(enc, (DRONE_HOST, PORT_DRONE_LISTEN_ENCRYPTED_CMD))
        except Exception as e:
            print(f"[KYBER-768 GCS] Command thread error: {e}")
            time.sleep(0.1)


if __name__ == "__main__":
    print("--- GCS KYBER-768 (ML-KEM-768) PROXY ---")
    t1 = threading.Thread(target=drone_to_gcs_thread, daemon=True)
    t2 = threading.Thread(target=gcs_to_drone_thread, daemon=True)
    t1.start()
    t2.start()
    print("READY")
    t1.join()
    t2.join()