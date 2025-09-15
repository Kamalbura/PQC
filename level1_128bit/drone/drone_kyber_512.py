# ==============================================================================
# drone_kyber_512.py
#
# Drone-Side Proxy for Post-Quantum Key Exchange using ML-KEM-512 (Kyber-512)
# NIST Security Level 1
# ==============================================================================

import socket
import threading
import os
import time
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from ip_config import *
import oqs.oqs as oqs

print("[KYBER-512 Drone] Starting Key Exchange (ML-KEM-512)...")

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

kem = oqs.KeyEncapsulation("ML-KEM-512")

ex_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
while True:
    try:
        ex_sock.connect((GCS_HOST, PORT_KEY_EXCHANGE))
        break
    except ConnectionRefusedError:
        print("[KYBER-512 Drone] GCS not ready, retry in 2s...")
        time.sleep(2)

print(f"[KYBER-512 Drone] Connected to {GCS_HOST}:{PORT_KEY_EXCHANGE}")
gcs_public_key = _recv_with_len(ex_sock)
ciphertext, shared_secret = kem.encap_secret(gcs_public_key)
_send_with_len(ex_sock, ciphertext)
AES_KEY = hashlib.sha256(shared_secret).digest()
ex_sock.close()

aesgcm = AESGCM(AES_KEY)
print("✅ [KYBER-512 Drone] Shared key established")


def encrypt_message(plaintext: bytes) -> bytes:
    nonce = os.urandom(NONCE_IV_SIZE)
    ct = aesgcm.encrypt(nonce, plaintext, None)
    return nonce + ct


def decrypt_message(encrypted_message: bytes):
    try:
        nonce = encrypted_message[:NONCE_IV_SIZE]
        ct = encrypted_message[NONCE_IV_SIZE:]
        return aesgcm.decrypt(nonce, ct, None)
    except Exception as e:
        print(f"[KYBER-512 Drone] Decryption failed: {e}")
        return None


def telemetry_to_gcs_thread():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((DRONE_HOST, PORT_DRONE_LISTEN_PLAINTEXT_TLM))
    print(f"[KYBER-512 Drone] Listening plaintext TLM on {DRONE_HOST}:{PORT_DRONE_LISTEN_PLAINTEXT_TLM}")
    while True:
        data, _ = sock.recvfrom(65535)
        enc = encrypt_message(data)
        sock.sendto(enc, (GCS_HOST, PORT_GCS_LISTEN_ENCRYPTED_TLM))


def commands_from_gcs_thread():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((DRONE_HOST, PORT_DRONE_LISTEN_ENCRYPTED_CMD))
    print(f"[KYBER-512 Drone] Listening encrypted CMD on {DRONE_HOST}:{PORT_DRONE_LISTEN_ENCRYPTED_CMD}")
    while True:
        data, _ = sock.recvfrom(65535)
        pt = decrypt_message(data)
        if pt:
            sock.sendto(pt, (DRONE_HOST, PORT_DRONE_FORWARD_DECRYPTED_CMD))


if __name__ == "__main__":
    print("--- DRONE KYBER-512 (ML-KEM-512) PROXY ---")
    t1 = threading.Thread(target=telemetry_to_gcs_thread, daemon=True)
    t2 = threading.Thread(target=commands_from_gcs_thread, daemon=True)
    t1.start()
    t2.start()
    t1.join()
    t2.join()