# ==============================================================================
# drone_camellia.py
#
# Drone-Side Proxy for Camellia Cryptography (CBC Mode)
#
# PURPOSE:
#   Mirrors the GCS-side proxy for Camellia, performing the opposite
#   encryption/decryption operations for the two MAVLink streams.
#
# SECURITY WARNING:
#   This implementation uses CBC mode, which provides confidentiality but NOT
#   authenticity. A separate Message Authentication Code (MAC) is required
#   for a secure production system.
#
# DEPENDENCIES:
#   - cryptography (pip install cryptography)
#   - ip_config.py
# ==============================================================================

import socket
import threading
import os
import time
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from ip_config import *

## 1. YOUR CUSTOM CAMELLIA IMPLEMENTATION ##
class CustomCamelliaCipher:
    def __init__(self, key):
        if len(key) not in (16, 24, 32):
            raise ValueError("Key must be 16, 24, or 32 bytes.")
        self.key = key
        self.block_size = 128

    def encrypt(self, plaintext, iv):
        padder = PKCS7(self.block_size).padder()
        padded_data = padder.update(plaintext) + padder.finalize()
        cipher = Cipher(algorithms.Camellia(self.key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        return encryptor.update(padded_data) + encryptor.finalize()

    def decrypt(self, ciphertext, iv):
        cipher = Cipher(algorithms.Camellia(self.key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = PKCS7(self.block_size).unpadder()
        return unpadder.update(padded_plaintext) + unpadder.finalize()

## 2. CONFIGURATION ##
# Hardcoded key for research - must match GCS
PSK_CAMELLIA = b'MySecureCamelliaKey_16Bytes12345'  # 32 bytes for Camellia-256
camellia_cipher = CustomCamelliaCipher(PSK_CAMELLIA)

print("✅ [Camellia Drone] Using hardcoded key for research")

## 3. CRYPTOGRAPHY FUNCTIONS ##
def encrypt_message(plaintext):
    """Encrypts using Camellia-CBC, prepending a random 16-byte IV."""
    iv = os.urandom(16)
    ciphertext = camellia_cipher.encrypt(plaintext, iv)
    return iv + ciphertext

def decrypt_message(encrypted_message):
    """Decrypts using Camellia-CBC after splitting the IV."""
    try:
        if len(encrypted_message) < 16:
            return None
        iv = encrypted_message[:16]
        ciphertext = encrypted_message[16:]
        return camellia_cipher.decrypt(ciphertext, iv)
    except Exception as e:
        print(f"[Camellia Drone] Decryption failed: {e}")
        return None

## 4. NETWORKING THREADS ##
def telemetry_to_gcs_thread():
    """Thread 1: Encrypt outgoing telemetry from flight controller to GCS"""
    listen_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        listen_sock.bind((DRONE_HOST, PORT_DRONE_LISTEN_PLAINTEXT_TLM))
    except OSError as e:
        print(f"[CAMELLIA Drone] UDP bind failed on {DRONE_HOST}:{PORT_DRONE_LISTEN_PLAINTEXT_TLM} -> {e}; using 0.0.0.0")
        listen_sock.bind(("0.0.0.0", PORT_DRONE_LISTEN_PLAINTEXT_TLM))
    
    send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    print(f"[Camellia Drone] Listening for telemetry on {DRONE_HOST}:{PORT_DRONE_LISTEN_PLAINTEXT_TLM}")
    print(f"[Camellia Drone] Forwarding encrypted TLM to {GCS_HOST}:{PORT_GCS_LISTEN_ENCRYPTED_TLM}")
    
    while True:
        try:
            plaintext_data, addr = listen_sock.recvfrom(4096)
            encrypted_telemetry = encrypt_message(plaintext_data)
            send_sock.sendto(encrypted_telemetry, (GCS_HOST, PORT_GCS_LISTEN_ENCRYPTED_TLM))
        except Exception as e:
            print(f"[Camellia Drone] Telemetry thread error: {e}")
            time.sleep(0.1)

def commands_from_gcs_thread():
    """Thread 2: Decrypt incoming commands from GCS to flight controller"""
    listen_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        listen_sock.bind((DRONE_HOST, PORT_DRONE_LISTEN_ENCRYPTED_CMD))
    except OSError as e:
        print(f"[CAMELLIA Drone] UDP bind failed on {DRONE_HOST}:{PORT_DRONE_LISTEN_ENCRYPTED_CMD} -> {e}; using 0.0.0.0")
        listen_sock.bind(("0.0.0.0", PORT_DRONE_LISTEN_ENCRYPTED_CMD))
    
    forward_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    print(f"[Camellia Drone] Listening for GCS commands on {DRONE_HOST}:{PORT_DRONE_LISTEN_ENCRYPTED_CMD}")
    print(f"[Camellia Drone] Forwarding decrypted CMD to {DRONE_HOST}:{PORT_DRONE_FORWARD_DECRYPTED_CMD}")
    
    while True:
        try:
            encrypted_data, addr = listen_sock.recvfrom(4096)
            plaintext_command = decrypt_message(encrypted_data)
            if plaintext_command:
                forward_sock.sendto(plaintext_command, (DRONE_HOST, PORT_DRONE_FORWARD_DECRYPTED_CMD))
        except Exception as e:
            print(f"[Camellia Drone] Command thread error: {e}")
            time.sleep(0.1)

## 5. MAIN LOGIC ##
if __name__ == "__main__":
    print("--- DRONE CAMELLIA PROXY ---")
    t1 = threading.Thread(target=telemetry_to_gcs_thread, daemon=True)
    t2 = threading.Thread(target=commands_from_gcs_thread, daemon=True)
    t1.start()
    t2.start()
    t1.join()
    t2.join()
