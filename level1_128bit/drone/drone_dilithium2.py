#!/usr/bin/env python3
"""
Post-Quantum Secure Drone Communication System
Drone-side Dilithium2 (ML-DSA-44) Signature Proxy

This proxy implements Dilithium2 post-quantum digital signatures for MAVLink traffic authentication.
Dilithium2 provides NIST Security Level 2 with lattice-based signatures using the Kyber key exchange.

Network Flow:
- Uses Kyber-768 for key encapsulation and session key establishment
- Signs outgoing MAVLink telemetry with Dilithium2 before encryption
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

from ip_config import *

ALGORITHM_NAME = "Dilithium2"
NONCE_IV_SIZE = 12
SIGNATURE_MARKER = b"DILITHIUM2_SIG"
MESSAGE_MARKER = b"DILITHIUM2_MSG"

dilithium = None
sig_public_key = None
gcs_public_key = None
cipher_suite = None

def setup_dilithium_and_kyber():
    global dilithium, sig_public_key
    try:
        import oqs.oqs as oqs
        dilithium = oqs.Signature("Dilithium2")
        sig_public_key = dilithium.generate_keypair()
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

def sign_message(message: bytes) -> bytes:
    try:
        return dilithium.sign(message)
    except Exception as e:
        print(f"[{ALGORITHM_NAME} Drone] Signing failed: {e}")
        return None

def verify_signature(message: bytes, signature: bytes, public_key: bytes) -> bool:
    """Verify Dilithium2 signature"""
    try:
        return dilithium.verify(message, signature, public_key)
    except Exception as e:
        print(f"[{ALGORITHM_NAME} Drone] Signature verification failed: {e}")
        return False

def encrypt_message(plaintext: bytes) -> bytes:
    """Encrypt message using AES-256-GCM"""
    nonce = os.urandom(NONCE_IV_SIZE)
    ciphertext = cipher_suite.encrypt(nonce, plaintext, None)
    return nonce + ciphertext

def decrypt_message(encrypted_message: bytes) -> bytes:
    """Decrypt message using AES-256-GCM"""
    try:
        nonce = encrypted_message[:NONCE_IV_SIZE]
        ciphertext = encrypted_message[NONCE_IV_SIZE:]
        return cipher_suite.decrypt(nonce, ciphertext, None)
    except Exception as e:
        print(f"[{ALGORITHM_NAME} Drone] Decryption failed: {e}")
        return None

def telemetry_to_gcs_thread():
    """Thread 1: Sign and encrypt outgoing telemetry from drone applications to GCS"""
    # Listen for plaintext telemetry from drone applications
    listen_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listen_sock.bind((DRONE_HOST, PORT_DRONE_LISTEN_PLAINTEXT_TLM))
    
    # Socket to send signed+encrypted telemetry to GCS
    send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    print(f"[{ALGORITHM_NAME} Drone] Telemetry signing thread started")
    print(f"[{ALGORITHM_NAME} Drone] Listening for plaintext telemetry on {DRONE_HOST}:{PORT_DRONE_LISTEN_PLAINTEXT_TLM}")
    print(f"[{ALGORITHM_NAME} Drone] Forwarding signed+encrypted telemetry to {GCS_HOST}:{PORT_GCS_LISTEN_ENCRYPTED_TLM}")
    
    while True:
        try:
            # Receive plaintext telemetry
            plaintext, addr = listen_sock.recvfrom(65535)
            
            # Sign the message
            signature = sign_message(plaintext)
            if signature is None:
                continue
            
            # Create signed message: MARKER + signature_length + signature + message
            signed_message = (SIGNATURE_MARKER + 
                            len(signature).to_bytes(4, 'big') + 
                            signature + 
                            MESSAGE_MARKER + 
                            plaintext)
            
            # Encrypt the entire signed message
            encrypted = encrypt_message(signed_message)
            
            # Forward to GCS
            send_sock.sendto(encrypted, (GCS_HOST, PORT_GCS_LISTEN_ENCRYPTED_TLM))
            
        except Exception as e:
            print(f"[{ALGORITHM_NAME} Drone] Telemetry signing error: {e}")

def commands_from_gcs_thread():
    """Thread 2: Decrypt and verify incoming commands from GCS to drone applications"""
    # Listen for encrypted commands from GCS
    listen_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listen_sock.bind((DRONE_HOST, PORT_DRONE_LISTEN_ENCRYPTED_CMD))
    
    # Socket to send verified plaintext commands to drone applications
    send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    print(f"[{ALGORITHM_NAME} Drone] Command verification thread started")
    print(f"[{ALGORITHM_NAME} Drone] Listening for encrypted commands on {DRONE_HOST}:{PORT_DRONE_LISTEN_ENCRYPTED_CMD}")
    print(f"[{ALGORITHM_NAME} Drone] Forwarding verified commands to {DRONE_HOST}:{PORT_DRONE_FORWARD_DECRYPTED_CMD}")
    
    while True:
        try:
            # Receive encrypted command
            encrypted, addr = listen_sock.recvfrom(65535)
            
            # Decrypt message
            decrypted = decrypt_message(encrypted)
            if decrypted is None:
                continue
            
            # Parse signed message
            if not decrypted.startswith(SIGNATURE_MARKER):
                print(f"[{ALGORITHM_NAME} Drone] Invalid message format")
                continue
            
            # Extract signature length
            sig_len = int.from_bytes(decrypted[len(SIGNATURE_MARKER):len(SIGNATURE_MARKER)+4], 'big')
            
            # Extract signature
            sig_start = len(SIGNATURE_MARKER) + 4
            signature = decrypted[sig_start:sig_start + sig_len]
            
            # Extract message
            msg_start = sig_start + sig_len + len(MESSAGE_MARKER)
            if decrypted[sig_start + sig_len:msg_start] != MESSAGE_MARKER:
                print(f"[{ALGORITHM_NAME} Drone] Invalid message marker")
                continue
            
            plaintext = decrypted[msg_start:]
            
            # Verify signature
            if verify_signature(plaintext, signature, gcs_public_key):
                # Forward verified message to drone application
                send_sock.sendto(plaintext, (DRONE_HOST, PORT_DRONE_FORWARD_DECRYPTED_CMD))
            else:
                print(f"[{ALGORITHM_NAME} Drone] Signature verification failed - message rejected")
            
        except Exception as e:
            print(f"[{ALGORITHM_NAME} Drone] Command verification error: {e}")

def main():
    print(f"=== {ALGORITHM_NAME} Drone Proxy Starting ===")
    print(f"Algorithm: Dilithium2 (ML-DSA-44)")
    print(f"Security Level: NIST Level 2")
    print(f"Key Exchange: Kyber-768")
    print(f"Features: Digital signatures + AES-256-GCM encryption")
    print(f"Library: liboqs (quantum-secure)")
    print()
    
    try:
        # Initialize Dilithium2 and Kyber
        setup_dilithium_and_kyber()
        
        # Establish session key and exchange public keys
        setup_key_exchange()
        
        # Start proxy threads
        t1 = threading.Thread(target=telemetry_to_gcs_thread, daemon=True)
        t2 = threading.Thread(target=commands_from_gcs_thread, daemon=True)
        
        t1.start()
        t2.start()
        
        print(f"[{ALGORITHM_NAME} Drone] All threads started successfully")
        print(f"[{ALGORITHM_NAME} Drone] Proxy operational - Press Ctrl+C to stop\n")
        
        # Keep main thread alive
        while True:
            time.sleep(1)
            
    except KeyboardInterrupt:
        print(f"\n[{ALGORITHM_NAME} Drone] Shutting down...")
    except Exception as e:
        print(f"[{ALGORITHM_NAME} Drone] Critical error: {e}")

if __name__ == "__main__":
    main()