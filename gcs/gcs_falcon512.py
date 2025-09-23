#!/usr/bin/env python3
"""
Post-Quantum Secure Drone Communication System
GCS-side Falcon-512 Signature Proxy

This proxy implements Falcon-512 post-quantum digital signatures for MAVLink traffic authentication.
Falcon-512 targets NIST Security Level 1 and uses Kyber-768 for session key establishment.

Network Flow:
- Uses Kyber-768 for key encapsulation and session key establishment
- Signs outgoing MAVLink commands with Falcon-512 before encryption
- Verifies incoming MAVLink telemetry signatures after decryption
- Forwards authenticated messages between GCS applications and drone

Author: AI Coding Agent
Date: September 14, 2025
"""

import socket
import threading
import time
import os
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Import network configuration
from ip_config import *

# Algorithm-specific constants
ALGORITHM_NAME = "Falcon-512"
NONCE_IV_SIZE = 12
SIGNATURE_MARKER = b"FALCON512_SIG"
MESSAGE_MARKER = b"FALCON512_MSG"

# Global variables
falcon = None
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


def _recv_with_len(conn: socket.socket) -> bytes:
    n = int.from_bytes(_recv_exact(conn, 4), 'big')
    return _recv_exact(conn, n)


def _send_with_len(conn: socket.socket, data: bytes):
    conn.sendall(len(data).to_bytes(4, 'big'))
    conn.sendall(data)


def setup_falcon_and_kyber():
    """Initialize Falcon-512 and ML-KEM-768 using liboqs"""
    global falcon, sig_public_key

    try:
        import oqs.oqs as oqs
        falcon = oqs.Signature("Falcon-512")
        sig_public_key = falcon.generate_keypair()
        print(f"[{ALGORITHM_NAME} GCS] liboqs initialized successfully")
        print(f"[{ALGORITHM_NAME} GCS] Public key: {len(sig_public_key)} bytes")
    except ImportError:
        raise RuntimeError(f"[{ALGORITHM_NAME} GCS] liboqs is required. Please install liboqs-python.")


def setup_key_exchange():
    """Establish session key via ML-KEM-768 KEM and exchange Falcon-512 public keys"""
    global drone_public_key, cipher_suite

    print(f"[{ALGORITHM_NAME} GCS] Setting up key exchange server...")

    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server_sock.bind((GCS_HOST, PORT_KEY_EXCHANGE))
    except OSError as e:
        print(f"[{ALGORITHM_NAME} GCS] bind failed on {GCS_HOST}:{PORT_KEY_EXCHANGE} -> {e}; falling back to 0.0.0.0")
        server_sock.bind(("0.0.0.0", PORT_KEY_EXCHANGE))
    server_sock.listen(1)

    print(f"[{ALGORITHM_NAME} GCS] Waiting for drone connection on {GCS_HOST}:{PORT_KEY_EXCHANGE}")

    try:
        while True:
            conn, addr = server_sock.accept()
            print(f"[{ALGORITHM_NAME} GCS] Drone connected from {addr}")
            try:
                import oqs.oqs as oqs
                kem = oqs.KeyEncapsulation("ML-KEM-768")
                kyber_public = kem.generate_keypair()
                _send_with_len(conn, kyber_public)
                ciphertext = _recv_with_len(conn)
                shared_secret = kem.decap_secret(ciphertext)
                aes_key = hashlib.sha256(shared_secret).digest()
                cipher_suite = AESGCM(aes_key)
                print(f"[{ALGORITHM_NAME} GCS] ML-KEM-768 key exchange completed")
                drone_public_key = _recv_with_len(conn)
                _send_with_len(conn, sig_public_key)
                print(f"[{ALGORITHM_NAME} GCS] Falcon-512 public key exchange completed: Drone pk = {len(drone_public_key)} bytes")
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
        server_sock.close()


def sign_message(message: bytes) -> bytes:
    try:
        return falcon.sign(message)
    except Exception as e:
        print(f"[{ALGORITHM_NAME} GCS] Signing failed: {e}")
        return None


def verify_signature(message: bytes, signature: bytes, public_key: bytes) -> bool:
    try:
        return falcon.verify(message, signature, public_key)
    except Exception as e:
        print(f"[{ALGORITHM_NAME} GCS] Signature verification failed: {e}")
        return False


def encrypt_message(plaintext: bytes) -> bytes:
    nonce = os.urandom(NONCE_IV_SIZE)
    return nonce + cipher_suite.encrypt(nonce, plaintext, None)


def decrypt_message(encrypted_message: bytes) -> bytes:
    try:
        nonce = encrypted_message[:NONCE_IV_SIZE]
        ct = encrypted_message[NONCE_IV_SIZE:]
        return cipher_suite.decrypt(nonce, ct, None)
    except Exception as e:
        print(f"[{ALGORITHM_NAME} GCS] Decryption failed: {e}")
        return None


def commands_to_drone_thread():
    listen_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        listen_sock.bind((GCS_HOST, PORT_GCS_LISTEN_PLAINTEXT_CMD))
    except OSError as e:
        print(f"[{ALGORITHM_NAME} GCS] UDP bind failed on {GCS_HOST}:{PORT_GCS_LISTEN_PLAINTEXT_CMD} -> {e}; using 0.0.0.0")
        listen_sock.bind(("0.0.0.0", PORT_GCS_LISTEN_PLAINTEXT_CMD))

    send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    print(f"[{ALGORITHM_NAME} GCS] Command signing thread started")
    print(f"[{ALGORITHM_NAME} GCS] Listening for plaintext commands on {GCS_HOST}:{PORT_GCS_LISTEN_PLAINTEXT_CMD}")
    print(f"[{ALGORITHM_NAME} GCS] Forwarding signed+encrypted commands to {DRONE_HOST}:{PORT_DRONE_LISTEN_ENCRYPTED_CMD}")

    while True:
        try:
            plaintext, _ = listen_sock.recvfrom(65535)
            signature = sign_message(plaintext)
            if signature is None:
                continue
            signed_message = (
                SIGNATURE_MARKER +
                len(signature).to_bytes(4, 'big') +
                signature +
                MESSAGE_MARKER +
                plaintext
            )
            encrypted = encrypt_message(signed_message)
            send_sock.sendto(encrypted, (DRONE_HOST, PORT_DRONE_LISTEN_ENCRYPTED_CMD))
        except Exception as e:
            print(f"[{ALGORITHM_NAME} GCS] Command signing error: {e}")


def telemetry_from_drone_thread():
    listen_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        listen_sock.bind((GCS_HOST, PORT_GCS_LISTEN_ENCRYPTED_TLM))
    except OSError as e:
        print(f"[{ALGORITHM_NAME} GCS] UDP bind failed on {GCS_HOST}:{PORT_GCS_LISTEN_ENCRYPTED_TLM} -> {e}; using 0.0.0.0")
        listen_sock.bind(("0.0.0.0", PORT_GCS_LISTEN_ENCRYPTED_TLM))

    send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    print(f"[{ALGORITHM_NAME} GCS] Telemetry verification thread started")
    print(f"[{ALGORITHM_NAME} GCS] Listening for encrypted telemetry on {GCS_HOST}:{PORT_GCS_LISTEN_ENCRYPTED_TLM}")
    print(f"[{ALGORITHM_NAME} GCS] Forwarding verified telemetry to {GCS_HOST}:{PORT_GCS_FORWARD_DECRYPTED_TLM}")

    while True:
        try:
            encrypted, _ = listen_sock.recvfrom(65535)
            decrypted = decrypt_message(encrypted)
            if decrypted is None:
                continue
            if not decrypted.startswith(SIGNATURE_MARKER):
                print(f"[{ALGORITHM_NAME} GCS] Invalid message format")
                continue
            sig_len = int.from_bytes(decrypted[len(SIGNATURE_MARKER):len(SIGNATURE_MARKER)+4], 'big')
            sig_start = len(SIGNATURE_MARKER) + 4
            signature = decrypted[sig_start:sig_start+sig_len]
            msg_start = sig_start + sig_len + len(MESSAGE_MARKER)
            if decrypted[sig_start+sig_len:msg_start] != MESSAGE_MARKER:
                print(f"[{ALGORITHM_NAME} GCS] Invalid message marker")
                continue
            plaintext = decrypted[msg_start:]
            if verify_signature(plaintext, signature, drone_public_key):
                send_sock.sendto(plaintext, (GCS_HOST, PORT_GCS_FORWARD_DECRYPTED_TLM))
            else:
                print(f"[{ALGORITHM_NAME} GCS] Signature verification failed - message rejected")
        except Exception as e:
            print(f"[{ALGORITHM_NAME} GCS] Telemetry verification error: {e}")


def main():
    print(f"=== {ALGORITHM_NAME} GCS Proxy Starting ===")
    print(f"Security Level: NIST Level 1")
    print(f"Key Exchange: Kyber-768")
    print(f"Features: Digital signatures + AES-256-GCM encryption")
    print(f"Library: liboqs (quantum-secure)\n")

    try:
        setup_falcon_and_kyber()
        setup_key_exchange()
        t1 = threading.Thread(target=commands_to_drone_thread, daemon=True)
        t2 = threading.Thread(target=telemetry_from_drone_thread, daemon=True)
        t1.start(); t2.start()
        print(f"[{ALGORITHM_NAME} GCS] All threads started successfully\n")
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print(f"\n[{ALGORITHM_NAME} GCS] Shutting down...")
    except Exception as e:
        print(f"[{ALGORITHM_NAME} GCS] Critical error: {e}")


if __name__ == "__main__":
    main()
