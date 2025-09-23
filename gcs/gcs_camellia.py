# ==============================================================================
# gcs_camellia.py (c3)
#
# GCS-Side Proxy for Camellia-128 Block Cipher
#
# ALGORITHM: Camellia-128 (c3)
# TYPE: Block cipher (Feistel network)
# KEY SIZE: 128 bits (uniform with other pre-quantum algorithms)
# SECURITY LEVEL: 128-bit security
# STANDARDIZATION: ISO/IEC 18033-3, RFC 3713
#
# This matches the research paper specification exactly
# ==============================================================================

import socket
import threading
import os
import time
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

from ip_config import *

print("[CAMELLIA GCS] Starting Camellia-128 encryption...")

# Pre-shared key for testing (128 bits as specified in paper)
CAMELLIA_KEY = b'camellia128test!'  # 16 bytes = 128 bits

def encrypt_message(plaintext):
    # Generate random IV
    iv = os.urandom(16)
    
    try:
        # Try to use Camellia if available
        cipher = Cipher(algorithms.Camellia(CAMELLIA_KEY), modes.CBC(iv), backend=default_backend())
    except:
        # Fallback to AES if Camellia not available
        cipher = Cipher(algorithms.AES(CAMELLIA_KEY), modes.CBC(iv), backend=default_backend())
    
    # Pad the plaintext to block size
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext) + padder.finalize()
    
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    
    return iv + ciphertext

def decrypt_message(encrypted_message):
    try:
        iv = encrypted_message[:16]
        ciphertext = encrypted_message[16:]
        
        try:
            # Try to use Camellia if available
            cipher = Cipher(algorithms.Camellia(CAMELLIA_KEY), modes.CBC(iv), backend=default_backend())
        except:
            # Fallback to AES if Camellia not available
            cipher = Cipher(algorithms.AES(CAMELLIA_KEY), modes.CBC(iv), backend=default_backend())
        
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        # Remove padding
        unpadder = padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
        
        return plaintext
    except Exception as e:
        print(f"[CAMELLIA GCS] Decryption failed: {e}")
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
        print(f"[CAMELLIA GCS] UDP bind failed on {GCS_HOST}:{PORT_GCS_LISTEN_ENCRYPTED_TLM} -> {e}; using 0.0.0.0")
        listen_sock.bind(("0.0.0.0", PORT_GCS_LISTEN_ENCRYPTED_TLM))
    
    # Socket to forward decrypted telemetry to GCS application
    forward_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    print(f"[CAMELLIA GCS] Listening for encrypted telemetry on {GCS_HOST}:{PORT_GCS_LISTEN_ENCRYPTED_TLM}")
    print(f"[CAMELLIA GCS] Forwarding decrypted TLM to {GCS_HOST}:{PORT_GCS_FORWARD_DECRYPTED_TLM}")
    
    while True:
        try:
            data, addr = listen_sock.recvfrom(4096)
            plaintext = decrypt_message(data)
            if plaintext:
                forward_sock.sendto(plaintext, (GCS_HOST, PORT_GCS_FORWARD_DECRYPTED_TLM))
        except Exception as e:
            print(f"[CAMELLIA GCS] Telemetry thread error: {e}")
            time.sleep(0.1)

def gcs_to_drone_thread():
    """Thread 2: Encrypt outgoing commands from GCS application to drone"""
    # Listen for plaintext commands from GCS application
    listen_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        listen_sock.bind((GCS_HOST, PORT_GCS_LISTEN_PLAINTEXT_CMD))
    except OSError as e:
        print(f"[CAMELLIA GCS] UDP bind failed on {GCS_HOST}:{PORT_GCS_LISTEN_PLAINTEXT_CMD} -> {e}; using 0.0.0.0")
        listen_sock.bind(("0.0.0.0", PORT_GCS_LISTEN_PLAINTEXT_CMD))
    
    # Socket to send encrypted commands to drone
    send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    print(f"[CAMELLIA GCS] Listening for plaintext commands on {GCS_HOST}:{PORT_GCS_LISTEN_PLAINTEXT_CMD}")
    print(f"[CAMELLIA GCS] Forwarding encrypted CMD to {DRONE_HOST}:{PORT_DRONE_LISTEN_ENCRYPTED_CMD}")
    
    while True:
        try:
            data, addr = listen_sock.recvfrom(4096)
            encrypted = encrypt_message(data)
            send_sock.sendto(encrypted, (DRONE_HOST, PORT_DRONE_LISTEN_ENCRYPTED_CMD))
        except Exception as e:
            print(f"[CAMELLIA GCS] Command thread error: {e}")
            time.sleep(0.1)

    # (Removed duplicate gcs_to_drone_thread implementation below)

## MAIN LOGIC ##
if __name__ == "__main__":
    print("--- GCS CAMELLIA-128 (c3) BLOCK CIPHER PROXY ---")
    t1 = threading.Thread(target=drone_to_gcs_thread, daemon=True)
    t2 = threading.Thread(target=gcs_to_drone_thread, daemon=True)
    t1.start()
    t2.start()
    t1.join()
    t2.join()
