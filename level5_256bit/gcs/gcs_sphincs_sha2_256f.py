#!/usr/bin/env python3
"""
Post-Quantum Secure Drone Communication System
GCS-side SPHINCS+-SHA2-256f Signature Proxy

This proxy implements SPHINCS+-SHA2-256f stateless hash-based signatures for MAVLink authentication.
SPHINCS+ 256f ~ NIST Level 5.

Network Flow:
- Kyber-768 KEM for session key
- Signs outgoing commands with SPHINCS+-SHA2-256f
- Verifies incoming telemetry
- AES-256-GCM transport

Author: AI Coding Agent
Date: September 14, 2025
"""

import socket
import threading
import time
import os
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ip_config import *

ALGORITHM_NAME = "SPHINCS+-SHA2-256f-simple"
NONCE_IV_SIZE = 12
SIGNATURE_MARKER = b"SPX256F_SIG"
MESSAGE_MARKER = b"SPX256F_MSG"

spx = None
sig_public_key = None
drone_public_key = None
cipher_suite = None

def _recv_exact(conn: socket.socket, n: int) -> bytes:
    data = bytearray()
    while len(data) < n:
        chunk = conn.recv(n - len(data))
        if not chunk:
            raise ConnectionError("Socket closed while receiving data")
        data.extend(chunk)
    return bytes(data)

def _send_with_len(conn: socket.socket, data: bytes):
    conn.sendall(len(data).to_bytes(4, 'big'))
    conn.sendall(data)

def _recv_with_len(conn: socket.socket) -> bytes:
    n = int.from_bytes(_recv_exact(conn, 4), 'big')
    return _recv_exact(conn, n)


def setup_spx_and_kyber():
    global spx, sig_public_key
    try:
        import oqs.oqs as oqs
        spx = oqs.Signature("SPHINCS+-SHA2-256f-simple")
        sig_public_key = spx.generate_keypair()
        print(f"[{ALGORITHM_NAME} GCS] liboqs initialized. PK={len(sig_public_key)}")
    except ImportError:
        raise RuntimeError(f"[{ALGORITHM_NAME} GCS] liboqs is required. Please install liboqs-python.")


def setup_key_exchange():
    global drone_public_key, cipher_suite
    print(f"[{ALGORITHM_NAME} GCS] Starting key exchange server...")
    ex_srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ex_srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ex_srv.bind((GCS_HOST, PORT_KEY_EXCHANGE))
    ex_srv.listen(1)

    try:
        import oqs.oqs as oqs
        kem = oqs.KeyEncapsulation("ML-KEM-768")
        pk = kem.generate_keypair()
        _ = kem.export_secret_key()  # ensure secret present for decap
        while True:
            conn, addr = ex_srv.accept()
            print(f"[{ALGORITHM_NAME} GCS] Drone connected from {addr}")
            try:
                _send_with_len(conn, pk)
                ct = _recv_with_len(conn)
                ss = kem.decap_secret(ct)
                aes_key = hashlib.sha256(ss).digest()
                global cipher_suite
                cipher_suite = AESGCM(aes_key)
                # Exchange signature public keys (Drone sends first)
                global drone_public_key
                drone_public_key = _recv_with_len(conn)
                _send_with_len(conn, sig_public_key)
                print(f"[{ALGORITHM_NAME} GCS] Key exchange completed")
                conn.close()
                break
            except Exception as e:
                print(f"[{ALGORITHM_NAME} GCS] Key exchange attempt failed: {e}")
                try:
                    conn.close()
                except Exception:
                    pass
                continue
    finally:
        ex_srv.close()


def sign_message(m: bytes) -> bytes:
    try:
        return spx.sign(m)
    except Exception as e:
        print(f"[{ALGORITHM_NAME} GCS] Signing failed: {e}")
        return None


def verify_signature(m: bytes, s: bytes, pk: bytes) -> bool:
    try:
        return spx.verify(m, s, pk)
    except Exception as e:
        print(f"[{ALGORITHM_NAME} GCS] Verify failed: {e}")
        return False


def encrypt_message(pt: bytes) -> bytes:
    n = os.urandom(NONCE_IV_SIZE)
    return n + cipher_suite.encrypt(n, pt, None)


def decrypt_message(em: bytes) -> bytes:
    try:
        n = em[:NONCE_IV_SIZE]
        ct = em[NONCE_IV_SIZE:]
        return cipher_suite.decrypt(n, ct, None)
    except Exception as e:
        print(f"[{ALGORITHM_NAME} GCS] Decrypt failed: {e}")
        return None


def telemetry_from_drone_thread():
    ls = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ls.bind((GCS_HOST, PORT_GCS_LISTEN_ENCRYPTED_TLM))
    ss = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    print(f"[{ALGORITHM_NAME} GCS] Listening telemetry {GCS_HOST}:{PORT_GCS_LISTEN_ENCRYPTED_TLM} -> {GCS_HOST}:{PORT_GCS_FORWARD_DECRYPTED_TLM}")
    while True:
        try:
            enc, _ = ls.recvfrom(65535)
            dec = decrypt_message(enc)
            if dec is None or not dec.startswith(SIGNATURE_MARKER):
                print(f"[{ALGORITHM_NAME} GCS] Invalid message format")
                continue
            sig_len = int.from_bytes(dec[len(SIGNATURE_MARKER):len(SIGNATURE_MARKER)+4], 'big')
            sig_start = len(SIGNATURE_MARKER) + 4
            sig = dec[sig_start:sig_start+sig_len]
            msg_start = sig_start + sig_len + len(MESSAGE_MARKER)
            if dec[sig_start+sig_len:msg_start] != MESSAGE_MARKER:
                print(f"[{ALGORITHM_NAME} GCS] Invalid message marker")
                continue
            pt = dec[msg_start:]
            if verify_signature(pt, sig, drone_public_key):
                ss.sendto(pt, (GCS_HOST, PORT_GCS_FORWARD_DECRYPTED_TLM))
            else:
                print(f"[{ALGORITHM_NAME} GCS] Signature verification failed")
        except Exception as e:
            print(f"[{ALGORITHM_NAME} GCS] Telemetry error: {e}")


def commands_to_drone_thread():
    ls = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ls.bind((GCS_HOST, PORT_GCS_LISTEN_PLAINTEXT_CMD))
    ss = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    print(f"[{ALGORITHM_NAME} GCS] Listening commands {GCS_HOST}:{PORT_GCS_LISTEN_PLAINTEXT_CMD} -> {DRONE_HOST}:{PORT_DRONE_LISTEN_ENCRYPTED_CMD}")
    while True:
        try:
            pt, _ = ls.recvfrom(65535)
            sig = sign_message(pt)
            if sig is None:
                continue
            msg = SIGNATURE_MARKER + len(sig).to_bytes(4, 'big') + sig + MESSAGE_MARKER + pt
            enc = encrypt_message(msg)
            ss.sendto(enc, (DRONE_HOST, PORT_DRONE_LISTEN_ENCRYPTED_CMD))
        except Exception as e:
            print(f"[{ALGORITHM_NAME} GCS] Command error: {e}")


def main():
    print(f"=== {ALGORITHM_NAME} GCS Proxy Starting ===")
    print(f"Library: liboqs (quantum-secure)\n")
    try:
        setup_spx_and_kyber()
        setup_key_exchange()
        t1 = threading.Thread(target=telemetry_from_drone_thread, daemon=True)
        t2 = threading.Thread(target=commands_to_drone_thread, daemon=True)
        t1.start(); t2.start()
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print(f"\n[{ALGORITHM_NAME} GCS] Shutting down...")
    except Exception as e:
        print(f"[{ALGORITHM_NAME} GCS] Critical error: {e}")


if __name__ == "__main__":
    main()
