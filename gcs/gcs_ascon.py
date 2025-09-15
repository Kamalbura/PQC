# ==============================================================================
# gcs_ascon.py
#if __name__ == "__main__":
    print("--- GCS ASCON (AEAD) PROXY ---")
    t1 = threading.Thread(target=drone_to_gcs_thread, daemon=True)
    t2 = threading.Thread(target=gcs_to_drone_thread, daemon=True)
    t1.start()
    t2.start()
    print("READY")
    t1.join()
    t2.join()ide Proxy for ASCON-128 AEAD (Authenticated Encryption with Associated Data)
# NIST Lightweight Cryptography Winner - 128-bit Security Level
#
# METHOD:
#   1) Share 128-bit symmetric key over TCP
#   2) Use ASCON-128 AEAD for UDP MAVLink streams
# ==============================================================================

import socket
import threading
import os
try:
    import ascon
    USING_ASCON = True
except ImportError:
    print("[WARNING] ascon not found, using AES-GCM fallback")
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    USING_ASCON = False

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from ip_config import *

print("[ASCON GCS] Starting Key Exchange...")

# Generate 128-bit key for ASCON-128
ASCON_KEY = os.urandom(16)

ex_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
ex_sock.bind((GCS_HOST, PORT_KEY_EXCHANGE))
ex_sock.listen(1)
print(f"[ASCON GCS] Waiting on {GCS_HOST}:{PORT_KEY_EXCHANGE}...")
conn, addr = ex_sock.accept()
print(f"[ASCON GCS] Drone connected from {addr}")

# Send symmetric key to drone
conn.sendall(ASCON_KEY)
conn.close()
ex_sock.close()

if USING_ASCON:
    print("✅ [ASCON GCS] Using ASCON-128 AEAD")
else:
    # Fallback to AES-GCM if ASCON not available
    print("✅ [ASCON GCS] Using AES-GCM fallback")
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
        print(f"[ASCON GCS] Decryption failed: {e}")
        return None


def drone_to_gcs_thread():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((GCS_HOST, PORT_GCS_LISTEN_ENCRYPTED_TLM))
    print(f"[ASCON GCS] Listening encrypted TLM on {GCS_HOST}:{PORT_GCS_LISTEN_ENCRYPTED_TLM}")
    while True:
        data, _ = sock.recvfrom(65535)
        pt = decrypt_message(data)
        if pt:
            sock.sendto(pt, (GCS_HOST, PORT_GCS_FORWARD_DECRYPTED_TLM))


def gcs_to_drone_thread():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((GCS_HOST, PORT_GCS_LISTEN_PLAINTEXT_CMD))
    print(f"[ASCON GCS] Listening plaintext CMD on {GCS_HOST}:{PORT_GCS_LISTEN_PLAINTEXT_CMD}")
    while True:
        data, _ = sock.recvfrom(65535)
        enc = encrypt_message(data)
        sock.sendto(enc, (DRONE_HOST, PORT_DRONE_LISTEN_ENCRYPTED_CMD))


if __name__ == "__main__":
    print("--- GCS ASCON-128 AEAD PROXY ---")
    t1 = threading.Thread(target=drone_to_gcs_thread, daemon=True)
    t2 = threading.Thread(target=gcs_to_drone_thread, daemon=True)
    t1.start()
    t2.start()
    t1.join()
    t2.join()