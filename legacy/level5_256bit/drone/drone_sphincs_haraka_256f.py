#!/usr/bin/env python3
"""
Post-Quantum Secure Drone Communication System
Drone-side SPHINCS+-Haraka-256f Signature Proxy

This proxy implements SPHINCS+-Haraka-256f stateless hash-based signatures for MAVLink authentication.
SPHINCS+ 256f ~ NIST Level 5.

Network Flow:
- Kyber-768 KEM for session key
- Signs outgoing telemetry with SPHINCS+-Haraka-256f
- Verifies incoming commands
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

ALGORITHM_NAME = "SPHINCS+-Haraka-256f-simple"
NONCE_IV_SIZE = 12
SIGNATURE_MARKER = b"SPXH256F_SIG"
MESSAGE_MARKER = b"SPXH256F_MSG"

spx = None
sig_public_key = None
gcs_public_key = None
cipher_suite = None


def setup_spx_and_kyber():
    global spx, sig_public_key
    try:
        import oqs.oqs as oqs
        spx = oqs.Signature("SPHINCS+-Haraka-256f-simple")
        sig_public_key = spx.generate_keypair()
        print(f"[{ALGORITHM_NAME} Drone] liboqs initialized. PK={len(sig_public_key)}")
    except ImportError:
        raise RuntimeError(f"[{ALGORITHM_NAME} Drone] liboqs is required. Please install liboqs-python.")

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


def setup_key_exchange():
    global gcs_public_key, cipher_suite
    print(f"[{ALGORITHM_NAME} Drone] Setting up key exchange with GCS...")
    ex_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ex_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    while True:
        try:
            ex_sock.connect((GCS_HOST, PORT_KEY_EXCHANGE))
            break
        except ConnectionRefusedError:
            print(f"[{ALGORITHM_NAME} Drone] GCS not ready, retry in 2s...")
            time.sleep(2)
    try:
        import oqs.oqs as oqs
        kem = oqs.KeyEncapsulation("ML-KEM-768")
        gcs_kyber_public = _recv_with_len(ex_sock)
        ct, ss = kem.encap_secret(gcs_kyber_public)
        _send_with_len(ex_sock, ct)
        aes_key = hashlib.sha256(ss).digest()
        global cipher_suite
        cipher_suite = AESGCM(aes_key)
        _send_with_len(ex_sock, sig_public_key)
        global gcs_public_key
        gcs_public_key = _recv_with_len(ex_sock)
        print(f"[{ALGORITHM_NAME} Drone] Key exchange completed")
    except Exception as e:
        print(f"[{ALGORITHM_NAME} Drone] Key exchange failed: {e}")
        raise
    finally:
        ex_sock.close()


def sign_message(m: bytes) -> bytes:
    try:
        return spx.sign(m)
    except Exception as e:
        print(f"[{ALGORITHM_NAME} Drone] Signing failed: {e}")
        return None


def verify_signature(m: bytes, s: bytes, pk: bytes) -> bool:
    try:
        return spx.verify(m, s, pk)
    except Exception as e:
        print(f"[{ALGORITHM_NAME} Drone] Verify failed: {e}")
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
        print(f"[{ALGORITHM_NAME} Drone] Decrypt failed: {e}")
        return None


def telemetry_to_gcs_thread():
    ls = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ls.bind((DRONE_HOST, PORT_DRONE_LISTEN_PLAINTEXT_TLM))
    ss = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    print(f"[{ALGORITHM_NAME} Drone] Listening telemetry {DRONE_HOST}:{PORT_DRONE_LISTEN_PLAINTEXT_TLM} -> {GCS_HOST}:{PORT_GCS_LISTEN_ENCRYPTED_TLM}")
    while True:
        try:
            pt, _ = ls.recvfrom(65535)
            sig = sign_message(pt)
            if sig is None:
                continue
            msg = SIGNATURE_MARKER + len(sig).to_bytes(4, 'big') + sig + MESSAGE_MARKER + pt
            enc = encrypt_message(msg)
            ss.sendto(enc, (GCS_HOST, PORT_GCS_LISTEN_ENCRYPTED_TLM))
        except Exception as e:
            print(f"[{ALGORITHM_NAME} Drone] Telemetry error: {e}")


def commands_from_gcs_thread():
    ls = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ls.bind((DRONE_HOST, PORT_DRONE_LISTEN_ENCRYPTED_CMD))
    ss = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    print(f"[{ALGORITHM_NAME} Drone] Listening commands {DRONE_HOST}:{PORT_DRONE_LISTEN_ENCRYPTED_CMD} -> {DRONE_HOST}:{PORT_DRONE_FORWARD_DECRYPTED_CMD}")
    while True:
        try:
            enc, _ = ls.recvfrom(65535)
            dec = decrypt_message(enc)
            if dec is None or not dec.startswith(SIGNATURE_MARKER):
                print(f"[{ALGORITHM_NAME} Drone] Invalid message format")
                continue
            sig_len = int.from_bytes(dec[len(SIGNATURE_MARKER):len(SIGNATURE_MARKER)+4], 'big')
            sig_start = len(SIGNATURE_MARKER) + 4
            sig = dec[sig_start:sig_start+sig_len]
            msg_start = sig_start + sig_len + len(MESSAGE_MARKER)
            if dec[sig_start+sig_len:msg_start] != MESSAGE_MARKER:
                print(f"[{ALGORITHM_NAME} Drone] Invalid message marker")
                continue
            pt = dec[msg_start:]
            if verify_signature(pt, sig, gcs_public_key):
                ss.sendto(pt, (DRONE_HOST, PORT_DRONE_FORWARD_DECRYPTED_CMD))
            else:
                print(f"[{ALGORITHM_NAME} Drone] Signature verification failed")
        except Exception as e:
            print(f"[{ALGORITHM_NAME} Drone] Command error: {e}")


def main():
    print(f"=== {ALGORITHM_NAME} Drone Proxy Starting ===")
    print(f"Library: liboqs (quantum-secure)\n")
    try:
        setup_spx_and_kyber()
        setup_key_exchange()
        t1 = threading.Thread(target=telemetry_to_gcs_thread, daemon=True)
        t2 = threading.Thread(target=commands_from_gcs_thread, daemon=True)
        t1.start(); t2.start()
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print(f"\n[{ALGORITHM_NAME} Drone] Shutting down...")
    except Exception as e:
        print(f"[{ALGORITHM_NAME} Drone] Critical error: {e}")


if __name__ == "__main__":
    main()
