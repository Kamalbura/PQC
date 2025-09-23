# ==============================================================================
# drone_kyber_768.py
#
# Drone-Side Proxy for Post-Quantum Key Exchange using ML-KEM-768 (Kyber-768)
# REFERENCE IMPLEMENTATION - Use as template for other Kyber variants
# 
# FIXES APPLIED:
# - Added connection timeout and retry limit
# - Proper error handling and logging
# - Thread synchronization with crypto initialization
# ==============================================================================

import socket
import threading
import os
import time
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from ip_config import *

print("[KYBER-768 Drone] Starting Key Exchange (ML-KEM-768)...")

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

def perform_key_exchange():
    """Perform key exchange with timeout and retry limit"""
    global aesgcm, crypto_ready
    
    kem = oqs.KeyEncapsulation("ML-KEM-768")
    max_retries = 30  # 60 seconds total
    retry_count = 0
    
    while retry_count < max_retries:
        try:
            ex_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            ex_sock.settimeout(5.0)  # 5 second connection timeout
            ex_sock.connect((GCS_HOST, PORT_KEY_EXCHANGE))
            
            print(f"[KYBER-768 Drone] Connected to {GCS_HOST}:{PORT_KEY_EXCHANGE}")
            gcs_public_key = _recv_with_len(ex_sock)
            ciphertext, shared_secret = kem.encap_secret(gcs_public_key)
            _send_with_len(ex_sock, ciphertext)
            AES_KEY = hashlib.sha256(shared_secret).digest()
            ex_sock.close()
            
            # Initialize crypto
            aesgcm = AESGCM(AES_KEY)
            crypto_ready.set()  # Signal threads that crypto is ready
            print("✅ [KYBER-768 Drone] Shared key established")
            return
            
        except (ConnectionRefusedError, socket.timeout, OSError) as e:
            retry_count += 1
            print(f"[KYBER-768 Drone] Connection attempt {retry_count}/{max_retries} failed: {e}")
            if retry_count < max_retries:
                time.sleep(2)
            try:
                ex_sock.close()
            except:
                pass
    
    raise RuntimeError(f"[KYBER-768 Drone] Could not connect to GCS after {max_retries} attempts")

# Perform key exchange before starting threads
perform_key_exchange()


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
        print(f"[KYBER-768 Drone] Decryption failed: {e}")
        return None


def telemetry_to_gcs_thread():
    """Thread 1: Encrypt outgoing telemetry from flight controller to GCS"""
    # Wait for crypto to be ready
    crypto_ready.wait()
    
    # Listen for plaintext telemetry from flight controller
    listen_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        listen_sock.bind((DRONE_HOST, PORT_DRONE_LISTEN_PLAINTEXT_TLM))
    except OSError as e:
        print(f"[KYBER-768 Drone] UDP bind failed on {DRONE_HOST}:{PORT_DRONE_LISTEN_PLAINTEXT_TLM} -> {e}; using 0.0.0.0")
        listen_sock.bind(("0.0.0.0", PORT_DRONE_LISTEN_PLAINTEXT_TLM))
    
    # Socket to send encrypted telemetry to GCS
    send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    print(f"[KYBER-768 Drone] Listening plaintext TLM on {DRONE_HOST}:{PORT_DRONE_LISTEN_PLAINTEXT_TLM}")
    print(f"[KYBER-768 Drone] Forwarding encrypted TLM to {GCS_HOST}:{PORT_GCS_LISTEN_ENCRYPTED_TLM}")
    
    while True:
        try:
            data, addr = listen_sock.recvfrom(65535)
            enc = encrypt_message(data)
            send_sock.sendto(enc, (GCS_HOST, PORT_GCS_LISTEN_ENCRYPTED_TLM))
        except Exception as e:
            print(f"[KYBER-768 Drone] Telemetry thread error: {e}")
            time.sleep(0.1)


def commands_from_gcs_thread():
    """Thread 2: Decrypt incoming commands from GCS to flight controller"""
    # Wait for crypto to be ready
    crypto_ready.wait()
    
    # Listen for encrypted commands from GCS
    listen_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        listen_sock.bind((DRONE_HOST, PORT_DRONE_LISTEN_ENCRYPTED_CMD))
    except OSError as e:
        print(f"[KYBER-768 Drone] UDP bind failed on {DRONE_HOST}:{PORT_DRONE_LISTEN_ENCRYPTED_CMD} -> {e}; using 0.0.0.0")
        listen_sock.bind(("0.0.0.0", PORT_DRONE_LISTEN_ENCRYPTED_CMD))
    
    # Socket to forward decrypted commands to flight controller
    forward_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    print(f"[KYBER-768 Drone] Listening encrypted CMD on {DRONE_HOST}:{PORT_DRONE_LISTEN_ENCRYPTED_CMD}")
    print(f"[KYBER-768 Drone] Forwarding decrypted CMD to {DRONE_HOST}:{PORT_DRONE_FORWARD_DECRYPTED_CMD}")
    
    while True:
        try:
            data, addr = listen_sock.recvfrom(65535)
            pt = decrypt_message(data)
            if pt:
                forward_sock.sendto(pt, (DRONE_HOST, PORT_DRONE_FORWARD_DECRYPTED_CMD))
        except Exception as e:
            print(f"[KYBER-768 Drone] Command thread error: {e}")
            time.sleep(0.1)


if __name__ == "__main__":
    print("--- DRONE KYBER-768 (ML-KEM-768) PROXY ---")
    t1 = threading.Thread(target=telemetry_to_gcs_thread, daemon=True)
    t2 = threading.Thread(target=commands_from_gcs_thread, daemon=True)
    t1.start()
    t2.start()
    print("READY") # Signal to parent process that sockets are listening
    t1.join()
    t2.join()