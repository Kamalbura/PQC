# ==============================================================================
# gcs_kyber_1024.py
#
# GCS-Side Proxy for Post-Quantum Key Exchange using ML-KEM-1024 (Kyber-1024)
# NIST Security Level 5
#
# METHOD:
#   1) Perform a Kyber (ML-KEM-1024) key exchange over TCP to derive a shared key.
#   2) Use AES-256-GCM with the derived key for UDP MAVLink streams.
# ==============================================================================

import socket
import threading
import os
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from ip_config import *
import oqs.oqs as oqs

print("[KYBER-1024 GCS] Starting Key Exchange (ML-KEM-1024)...")

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

kem = oqs.KeyEncapsulation("ML-KEM-1024")
gcs_public_key = kem.generate_keypair()

ex_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
ex_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
ex_sock.bind((GCS_HOST, PORT_KEY_EXCHANGE))
ex_sock.listen(1)
print(f"[KYBER-1024 GCS] Waiting on {GCS_HOST}:{PORT_KEY_EXCHANGE}...")
while True:
    conn, addr = ex_sock.accept()
    print(f"[KYBER-1024 GCS] Connection from {addr}")
    try:
        _send_with_len(conn, gcs_public_key)
        ciphertext = _recv_with_len(conn)
        ss = kem.decap_secret(ciphertext)
        AES_KEY = hashlib.sha256(ss).digest()
        conn.close()
        break
    except Exception as e:
        print(f"[KYBER-1024 GCS] Handshake failed for {addr}: {e}")
        try:
            conn.close()
        except Exception:
            pass
        continue

aesgcm = AESGCM(AES_KEY)
print("✅ [KYBER-1024 GCS] Shared key established")


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
        print(f"[KYBER-1024 GCS] Decryption failed: {e}")
        return None


def drone_to_gcs_thread():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((GCS_HOST, PORT_GCS_LISTEN_ENCRYPTED_TLM))
    print(f"[KYBER-1024 GCS] Listening encrypted TLM on {GCS_HOST}:{PORT_GCS_LISTEN_ENCRYPTED_TLM}")
    while True:
        data, _ = sock.recvfrom(65535)
        pt = decrypt_message(data)
        if pt:
            sock.sendto(pt, (GCS_HOST, PORT_GCS_FORWARD_DECRYPTED_TLM))


def gcs_to_drone_thread():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((GCS_HOST, PORT_GCS_LISTEN_PLAINTEXT_CMD))
    print(f"[KYBER-1024 GCS] Listening plaintext CMD on {GCS_HOST}:{PORT_GCS_LISTEN_PLAINTEXT_CMD}")
    while True:
        data, _ = sock.recvfrom(65535)
        enc = encrypt_message(data)
        sock.sendto(enc, (DRONE_HOST, PORT_DRONE_LISTEN_ENCRYPTED_CMD))


if __name__ == "__main__":
    print("--- GCS KYBER-1024 (ML-KEM-1024) PROXY ---")
    t1 = threading.Thread(target=drone_to_gcs_thread, daemon=True)
    t2 = threading.Thread(target=gcs_to_drone_thread, daemon=True)
    t1.start()
    t2.start()
    t1.join()
    t2.join()