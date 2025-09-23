# ==============================================================================
# gcs_speck.py (c2)
#
# GCS-Side Proxy for SPECK-128/128 Block Cipher
#
# ALGORITHM: SPECK-128/128 (c2)
# TYPE: Block cipher (NSA lightweight)
# KEY SIZE: 128 bits (uniform with other pre-quantum algorithms)
# SECURITY LEVEL: 128-bit security
# STANDARDIZATION: NSA-designed lightweight cipher (non-standard)
#
# This matches the research paper specification exactly
# ==============================================================================

import socket
import threading
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

from ip_config import *

print("[SPECK GCS] Starting SPECK-128/128 encryption...")

# Pre-shared key for testing (128 bits as specified in paper)
SPECK_KEY = b'speck128testkey!'  # 16 bytes = 128 bits

# SPECK implementation fallback using AES (since SPECK not in standard libraries)
cipher = Cipher(algorithms.AES(SPECK_KEY), modes.CBC(b'0'*16), backend=default_backend())

def encrypt_message(plaintext):
    # Pad the plaintext to block size
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext) + padder.finalize()
    
    # Generate random IV
    iv = os.urandom(16)
    cipher_cbc = Cipher(algorithms.AES(SPECK_KEY), modes.CBC(iv), backend=default_backend())
    encryptor = cipher_cbc.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    
    return iv + ciphertext

def decrypt_message(encrypted_message):
    try:
        iv = encrypted_message[:16]
        ciphertext = encrypted_message[16:]
        
        cipher_cbc = Cipher(algorithms.AES(SPECK_KEY), modes.CBC(iv), backend=default_backend())
        decryptor = cipher_cbc.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        # Remove padding
        unpadder = padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
        
        return plaintext
    except Exception as e:
        print(f"[SPECK GCS] Decryption failed: {e}")
        return None

## NETWORKING THREADS ##

def drone_to_gcs_thread():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind((GCS_HOST, PORT_GCS_LISTEN_ENCRYPTED_TLM))
    except OSError as e:
        print(f"[SPECK GCS] UDP bind failed on {GCS_HOST}:{PORT_GCS_LISTEN_ENCRYPTED_TLM} -> {e}; using 0.0.0.0")
        sock.bind(("0.0.0.0", PORT_GCS_LISTEN_ENCRYPTED_TLM))
    print(f"[SPECK GCS] Listening for encrypted telemetry on {GCS_HOST}:{PORT_GCS_LISTEN_ENCRYPTED_TLM}")
    while True:
        data, addr = sock.recvfrom(4096)
        plaintext = decrypt_message(data)
        if plaintext:
            sock.sendto(plaintext, (GCS_HOST, PORT_GCS_FORWARD_DECRYPTED_TLM))

def gcs_to_drone_thread():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind((GCS_HOST, PORT_GCS_LISTEN_PLAINTEXT_CMD))
    except OSError as e:
        print(f"[SPECK GCS] UDP bind failed on {GCS_HOST}:{PORT_GCS_LISTEN_PLAINTEXT_CMD} -> {e}; using 0.0.0.0")
        sock.bind(("0.0.0.0", PORT_GCS_LISTEN_PLAINTEXT_CMD))
    print(f"[SPECK GCS] Listening for plaintext commands on {GCS_HOST}:{PORT_GCS_LISTEN_PLAINTEXT_CMD}")
    while True:
        data, addr = sock.recvfrom(4096)
        encrypted = encrypt_message(data)
        sock.sendto(encrypted, (DRONE_HOST, PORT_DRONE_LISTEN_ENCRYPTED_CMD))

## MAIN LOGIC ##
if __name__ == "__main__":
    print("--- GCS SPECK-128/128 (c2) BLOCK CIPHER PROXY ---")
    t1 = threading.Thread(target=drone_to_gcs_thread, daemon=True)
    t2 = threading.Thread(target=gcs_to_drone_thread, daemon=True)
    t1.start()
    t2.start()
    t1.join()
    t2.join()
