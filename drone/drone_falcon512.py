#!/usr/bin/env python3
"""
Post-Quantum Secure Drone Communication System
Drone-side Falcon-512 Signature Proxy

This proxy implements Falcon-512 post-quantum digital signatures for MAVLink traffic authentication.
Falcon-512 targets NIST Security Level 1 and uses Kyber-768 for session key establishment.

Network Flow:
- Uses Kyber-768 for key encapsulation and session key establishment
- Signs outgoing MAVLink telemetry with Falcon-512 before encryption
- Verifies incoming MAVLink command signatures after decryption
- Forwards authenticated messages between drone applications and GCS

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
NONCE_IV_SIZE = 12  # GCM nonce size
SIGNATURE_MARKER = b"FALCON512_SIG"
MESSAGE_MARKER = b"FALCON512_MSG"

# Global variables
falcon = None
sig_public_key = None
gcs_public_key = None
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
        print(f"[{ALGORITHM_NAME} Drone] liboqs initialized successfully")
        print(f"[{ALGORITHM_NAME} Drone] Public key: {len(sig_public_key)} bytes")
    except ImportError:
        raise RuntimeError(f"[{ALGORITHM_NAME} Drone] liboqs is required. Please install liboqs-python.")


def setup_key_exchange():
    """Establish session key via ML-KEM-768 KEM and exchange Falcon-512 public keys"""
    global gcs_public_key, cipher_suite

    print(f"[{ALGORITHM_NAME} Drone] Setting up key exchange with GCS...")
    ex_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ex_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    while True:
        try:
            ex_sock.connect((GCS_HOST, PORT_KEY_EXCHANGE))
            print(f"[{ALGORITHM_NAME} Drone] Connected to GCS for key exchange")
            break
        except ConnectionRefusedError:
            print(f"[{ALGORITHM_NAME} Drone] GCS not ready, retrying in 2s...")
            time.sleep(2)

    try:
        import oqs.oqs as oqs
        kem = oqs.KeyEncapsulation("ML-KEM-768")

        # Receive GCS KEM public key (length-prefixed)
        gcs_kyber_public = _recv_with_len(ex_sock)

        # Encapsulate and send ciphertext (length-prefixed)
        ciphertext, shared_secret = kem.encap_secret(gcs_kyber_public)
        _send_with_len(ex_sock, ciphertext)

        # Derive AES-256-GCM key
        aes_key = hashlib.sha256(shared_secret).digest()
        cipher_suite = AESGCM(aes_key)
        print(f"[{ALGORITHM_NAME} Drone] ML-KEM-768 key exchange completed")

        # Exchange Falcon public keys (length-prefixed)
        _send_with_len(ex_sock, sig_public_key)
        gcs_public_key = _recv_with_len(ex_sock)
        print(f"[{ALGORITHM_NAME} Drone] Falcon-512 public key exchange completed: GCS pk = {len(gcs_public_key)} bytes")

    except Exception as e:
        print(f"[{ALGORITHM_NAME} Drone] Key exchange failed: {e}")
        raise
    finally:
        ex_sock.close()


def sign_message(message: bytes) -> bytes:
    try:
        return falcon.sign(message)
    except Exception as e:
        print(f"[{ALGORITHM_NAME} Drone] Signing failed: {e}")
        return None


def verify_signature(message: bytes, signature: bytes, public_key: bytes) -> bool:
    try:
        return falcon.verify(message, signature, public_key)
    except Exception as e:
        print(f"[{ALGORITHM_NAME} Drone] Signature verification failed: {e}")
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
        print(f"[{ALGORITHM_NAME} Drone] Decryption failed: {e}")
        return None


def telemetry_to_gcs_thread():
    # Listen for plaintext telemetry from drone applications
    listen_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        listen_sock.bind((DRONE_HOST, PORT_DRONE_LISTEN_PLAINTEXT_TLM))
    except OSError as e:
        print(f"[Falcon-512 Drone] UDP bind failed on {DRONE_HOST}:{PORT_DRONE_LISTEN_PLAINTEXT_TLM} -> {e}; using 0.0.0.0")
        listen_sock.bind(("0.0.0.0", PORT_DRONE_LISTEN_PLAINTEXT_TLM))

    # Socket to send signed+encrypted telemetry to GCS
    send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    print(f"[{ALGORITHM_NAME} Drone] Telemetry signing thread started")
    print(f"[{ALGORITHM_NAME} Drone] Listening for plaintext telemetry on {DRONE_HOST}:{PORT_DRONE_LISTEN_PLAINTEXT_TLM}")
    print(f"[{ALGORITHM_NAME} Drone] Forwarding signed+encrypted telemetry to {GCS_HOST}:{PORT_GCS_LISTEN_ENCRYPTED_TLM}")

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
            send_sock.sendto(encrypted, (GCS_HOST, PORT_GCS_LISTEN_ENCRYPTED_TLM))
        except Exception as e:
            print(f"[{ALGORITHM_NAME} Drone] Telemetry signing error: {e}")


def commands_from_gcs_thread():
    # Listen for encrypted commands from GCS
    listen_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        listen_sock.bind((DRONE_HOST, PORT_DRONE_LISTEN_ENCRYPTED_CMD))
    except OSError as e:
        print(f"[Falcon-512 Drone] UDP bind failed on {DRONE_HOST}:{PORT_DRONE_LISTEN_ENCRYPTED_CMD} -> {e}; using 0.0.0.0")
        listen_sock.bind(("0.0.0.0", PORT_DRONE_LISTEN_ENCRYPTED_CMD))

    # Socket to forward verified plaintext commands to drone apps
    send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    print(f"[{ALGORITHM_NAME} Drone] Command verification thread started")
    print(f"[{ALGORITHM_NAME} Drone] Listening for encrypted commands on {DRONE_HOST}:{PORT_DRONE_LISTEN_ENCRYPTED_CMD}")
    print(f"[{ALGORITHM_NAME} Drone] Forwarding verified commands to {DRONE_HOST}:{PORT_DRONE_FORWARD_DECRYPTED_CMD}")

    while True:
        try:
            encrypted, _ = listen_sock.recvfrom(65535)
            decrypted = decrypt_message(encrypted)
            if decrypted is None:
                continue
            if not decrypted.startswith(SIGNATURE_MARKER):
                print(f"[{ALGORITHM_NAME} Drone] Invalid message format")
                continue
            sig_len = int.from_bytes(decrypted[len(SIGNATURE_MARKER):len(SIGNATURE_MARKER)+4], 'big')
            sig_start = len(SIGNATURE_MARKER) + 4
            signature = decrypted[sig_start:sig_start+sig_len]
            msg_start = sig_start + sig_len + len(MESSAGE_MARKER)
            if decrypted[sig_start+sig_len:msg_start] != MESSAGE_MARKER:
                print(f"[{ALGORITHM_NAME} Drone] Invalid message marker")
                continue
            plaintext = decrypted[msg_start:]
            if verify_signature(plaintext, signature, gcs_public_key):
                send_sock.sendto(plaintext, (DRONE_HOST, PORT_DRONE_FORWARD_DECRYPTED_CMD))
            else:
                print(f"[{ALGORITHM_NAME} Drone] Signature verification failed - message rejected")
        except Exception as e:
            print(f"[{ALGORITHM_NAME} Drone] Command verification error: {e}")


def main():
    print(f"=== {ALGORITHM_NAME} Drone Proxy Starting ===")
    print(f"Security Level: NIST Level 1")
    print(f"Key Exchange: Kyber-768")
    print(f"Features: Digital signatures + AES-256-GCM encryption")
    print(f"Library: liboqs (quantum-secure)\n")

    try:
        setup_falcon_and_kyber()
        setup_key_exchange()
        t1 = threading.Thread(target=telemetry_to_gcs_thread, daemon=True)
        t2 = threading.Thread(target=commands_from_gcs_thread, daemon=True)
        t1.start(); t2.start()
        print(f"[{ALGORITHM_NAME} Drone] All threads started successfully\n")
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print(f"\n[{ALGORITHM_NAME} Drone] Shutting down...")
    except Exception as e:
        print(f"[{ALGORITHM_NAME} Drone] Critical error: {e}")


if __name__ == "__main__":
    main()
