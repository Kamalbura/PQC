# ==============================================================================
# gcs_ascon.py (c1)
#
# GCS-Side Proxy for ASCON-128 AEAD Cipher
#
# ALGORITHM: ASCON-128 (c1)
# TYPE: Authenticated Encryption with Associated Data (AEAD)
# KEY SIZE: 128 bits (uniform with other pre-quantum algorithms)
# SECURITY LEVEL: 128-bit security
# STANDARDIZATION: NIST SP 800-232 (Lightweight Cryptography Winner)
#
# This matches the research paper specification exactly
# ==============================================================================

import socket
import threading
import os
import time
try:
    from ascon import encrypt, decrypt
    USING_ASCON = True
except ImportError:
    print("[WARNING] ascon library not found, using AES-GCM fallback")
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    import secrets
    USING_ASCON = False

from ip_config import *

print("[ASCON GCS] Starting ASCON-128 AEAD encryption...")

# Pre-shared key for testing (128 bits as specified in paper)
ASCON_KEY = b'0123456789abcdef'  # 16 bytes = 128 bits

if USING_ASCON:
    print("[ASCON GCS] Using genuine ASCON-128 AEAD")
    
    def encrypt_message(plaintext):
        nonce = os.urandom(16)  # ASCON uses 16-byte nonce
        ciphertext = encrypt(ASCON_KEY, nonce, b'', plaintext)
        return nonce + ciphertext

    def decrypt_message(encrypted_message):
        try:
            nonce = encrypted_message[:16]
            ciphertext = encrypted_message[16:]
            return decrypt(ASCON_KEY, nonce, b'', ciphertext)
        except Exception as e:
            print(f"[ASCON GCS] Decryption failed: {e}")
            return None
else:
    print("[ASCON GCS] Using AES-GCM fallback")
    aesgcm = AESGCM(ASCON_KEY[:16])  # Use first 16 bytes
    
    def encrypt_message(plaintext):
        nonce = os.urandom(NONCE_IV_SIZE)
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)
        return nonce + ciphertext

    def decrypt_message(encrypted_message):
        try:
            nonce = encrypted_message[:NONCE_IV_SIZE]
            ciphertext = encrypted_message[NONCE_IV_SIZE:]
            return aesgcm.decrypt(nonce, ciphertext, None)
        except Exception as e:
            print(f"[ASCON GCS] Decryption failed: {e}")
            return None

## NETWORKING THREADS ##

def drone_to_gcs_thread():
    """Thread 1: Decrypt incoming telemetry from drone to GCS application"""
    # Listen for encrypted telemetry from drone
    listen_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        listen_sock.bind((GCS_HOST, PORT_GCS_LISTEN_ENCRYPTED_TLM))
    except OSError as e:
        print(f"[ASCON GCS] UDP bind failed on {GCS_HOST}:{PORT_GCS_LISTEN_ENCRYPTED_TLM} -> {e}; using 0.0.0.0")
        listen_sock.bind(("0.0.0.0", PORT_GCS_LISTEN_ENCRYPTED_TLM))
    
    # Socket to forward decrypted telemetry to GCS application
    forward_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    print(f"[ASCON GCS] Listening for encrypted telemetry on {GCS_HOST}:{PORT_GCS_LISTEN_ENCRYPTED_TLM}")
    print(f"[ASCON GCS] Forwarding decrypted TLM to {GCS_HOST}:{PORT_GCS_FORWARD_DECRYPTED_TLM}")
    
    while True:
        try:
            data, addr = listen_sock.recvfrom(4096)
            plaintext = decrypt_message(data)
            if plaintext:
                forward_sock.sendto(plaintext, (GCS_HOST, PORT_GCS_FORWARD_DECRYPTED_TLM))
        except Exception as e:
            print(f"[ASCON GCS] Telemetry thread error: {e}")
            time.sleep(0.1)

def gcs_to_drone_thread():
    """Thread 2: Encrypt outgoing commands from GCS application to drone"""
    # Listen for plaintext commands from GCS application
    listen_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        listen_sock.bind((GCS_HOST, PORT_GCS_LISTEN_PLAINTEXT_CMD))
    except OSError as e:
        print(f"[ASCON GCS] UDP bind failed on {GCS_HOST}:{PORT_GCS_LISTEN_PLAINTEXT_CMD} -> {e}; using 0.0.0.0")
        listen_sock.bind(("0.0.0.0", PORT_GCS_LISTEN_PLAINTEXT_CMD))
    
    # Socket to send encrypted commands to drone
    send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    print(f"[ASCON GCS] Listening for plaintext commands on {GCS_HOST}:{PORT_GCS_LISTEN_PLAINTEXT_CMD}")
    print(f"[ASCON GCS] Forwarding encrypted CMD to {DRONE_HOST}:{PORT_DRONE_LISTEN_ENCRYPTED_CMD}")
    
    while True:
        try:
            data, addr = listen_sock.recvfrom(4096)
            encrypted = encrypt_message(data)
            send_sock.sendto(encrypted, (DRONE_HOST, PORT_DRONE_LISTEN_ENCRYPTED_CMD))
        except Exception as e:
            print(f"[ASCON GCS] Command thread error: {e}")
            time.sleep(0.1)

## MAIN LOGIC ##
if __name__ == "__main__":
    print("--- GCS ASCON-128 (c1) AEAD PROXY ---")
    t1 = threading.Thread(target=drone_to_gcs_thread, daemon=True)
    t2 = threading.Thread(target=gcs_to_drone_thread, daemon=True)
    t1.start()
    t2.start()
    t1.join()
    t2.join()
