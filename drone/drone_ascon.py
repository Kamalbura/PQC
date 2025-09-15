# ==============================================================================
# drone_ascon.pif __name__ == "__main__":
    print("--- DRONE ASCON (AEAD) PROXY ---")
    t1 = threading.Thread(target=telemetry_to_gcs_thread, daemon=True)
    t2 = threading.Thread(target=commands_from_gcs_thread, daemon=True)
    t1.start()
    t2.start()
    print("READY") # Signal to parent process that sockets are listening
    t1.join()
    t2.join()Drone-Side Proxy for ASCON-128 AEAD (Authenticated Encryption with Associated Data)
# NIST Lightweight Cryptography Winner - 128-bit Security Level
# ==============================================================================

import socket
import threading
import os
import time
try:
    import ascon
    USING_ASCON = True
except ImportError:
    print("[WARNING] ascon not found, using AES-GCM fallback")
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    USING_ASCON = False

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from ip_config import *

print("[ASCON Drone] Starting Key Exchange...")

# Use simple key exchange for symmetric algorithm (normally would use Kyber for real deployment)
ex_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
while True:
    try:
        ex_sock.connect((GCS_HOST, PORT_KEY_EXCHANGE))
        break
    except ConnectionRefusedError:
        print("[ASCON Drone] GCS not ready, retry in 2s...")
        time.sleep(2)

print(f"[ASCON Drone] Connected to {GCS_HOST}:{PORT_KEY_EXCHANGE}")
# For symmetric algorithms, we use pre-shared or simple key exchange
ASCON_KEY = ex_sock.recv(16)  # 128-bit key for ASCON-128
ex_sock.close()

if USING_ASCON:
    print("✅ [ASCON Drone] Using ASCON-128 AEAD")
else:
    # Fallback to AES-GCM if ASCON not available
    print("✅ [ASCON Drone] Using AES-GCM fallback")
    # Extend 16-byte key to 32-byte for AES-256-GCM
    import hashlib
    extended_key = hashlib.sha256(ASCON_KEY).digest()
    aesgcm = AESGCM(extended_key)


def encrypt_message(plaintext: bytes) -> bytes:
    if USING_ASCON:
        nonce = os.urandom(16)  # 128-bit nonce for ASCON
        ciphertext = ascon.encrypt(ASCON_KEY, nonce, b"", plaintext)
        return nonce + ciphertext
    else:
        nonce = os.urandom(NONCE_IV_SIZE)
        ct = aesgcm.encrypt(nonce, plaintext, None)
        return nonce + ct


def decrypt_message(encrypted_message: bytes):
    try:
        if USING_ASCON:
            nonce = encrypted_message[:16]
            ciphertext = encrypted_message[16:]
            return ascon.decrypt(ASCON_KEY, nonce, b"", ciphertext)
        else:
            nonce = encrypted_message[:NONCE_IV_SIZE]
            ct = encrypted_message[NONCE_IV_SIZE:]
            return aesgcm.decrypt(nonce, ct, None)
    except Exception as e:
        print(f"[ASCON Drone] Decryption failed: {e}")
        return None


def telemetry_to_gcs_thread():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((DRONE_HOST, PORT_DRONE_LISTEN_PLAINTEXT_TLM))
    print(f"[ASCON Drone] Listening plaintext TLM on {DRONE_HOST}:{PORT_DRONE_LISTEN_PLAINTEXT_TLM}")
    while True:
        data, _ = sock.recvfrom(65535)
        enc = encrypt_message(data)
        sock.sendto(enc, (GCS_HOST, PORT_GCS_LISTEN_ENCRYPTED_TLM))


def commands_from_gcs_thread():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((DRONE_HOST, PORT_DRONE_LISTEN_ENCRYPTED_CMD))
    print(f"[ASCON Drone] Listening encrypted CMD on {DRONE_HOST}:{PORT_DRONE_LISTEN_ENCRYPTED_CMD}")
    while True:
        data, _ = sock.recvfrom(65535)
        pt = decrypt_message(data)
        if pt:
            sock.sendto(pt, (DRONE_HOST, PORT_DRONE_FORWARD_DECRYPTED_CMD))


if __name__ == "__main__":
    print("--- DRONE ASCON-128 AEAD PROXY ---")
    t1 = threading.Thread(target=telemetry_to_gcs_thread, daemon=True)
    t2 = threading.Thread(target=commands_from_gcs_thread, daemon=True)
    t1.start()
    t2.start()
    t1.join()
    t2.join()