#!/usr/bin/env python3
"""
Post-Quantum Secure Drone Communication System
GCS-side Dilithium2 (ML-DSA-44) Signature Proxy

This proxy implements Dilithium2 post-quantum digital signatures for MAVLink traffic authentication.
Dilithium2 provides NIST Security Level 2 with lattice-based signatures using the Kyber key exchange.

Network Flow:
- Uses Kyber-768 for key encapsulation and session key establishment
- Signs outgoing MAVLink commands with Dilithium2 before encryption  
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

from ip_config import *

# Backwards-compatible port aliases: ensure legacy constant names map to current ones
try:
    PORT_GCS_LISTEN_ENCRYPTED_TLM
except NameError:
    PORT_GCS_LISTEN_ENCRYPTED_TLM = PORT_GCS_FORWARD_DECRYPTED_TLM

try:
    PORT_DRONE_LISTEN_ENCRYPTED_CMD
except NameError:
    PORT_DRONE_LISTEN_ENCRYPTED_CMD = PORT_DRONE_FORWARD_DECRYPTED_CMD


ALGORITHM_NAME = "Dilithium2"
NONCE_IV_SIZE = 12
SIGNATURE_MARKER = b"DILITHIUM2_SIG"
MESSAGE_MARKER = b"DILITHIUM2_MSG"

dilithium = None
sig_public_key = None
drone_public_key = None
cipher_suite = None

def setup_dilithium_and_kyber():
    global dilithium, sig_public_key
    try:
        import oqs.oqs as oqs
        dilithium = oqs.Signature("Dilithium2")
        sig_public_key = dilithium.generate_keypair()
        print(f"[{ALGORITHM_NAME} GCS] liboqs initialized. PK={len(sig_public_key)}")
    except ImportError:
        raise RuntimeError(f"[{ALGORITHM_NAME} GCS] liboqs is required. Please install liboqs-python.")

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

def setup_key_exchange():
    global drone_public_key, cipher_suite
    print(f"[{ALGORITHM_NAME} GCS] Setting up key exchange server...")
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind((GCS_HOST, PORT_KEY_EXCHANGE))
    server_sock.listen(1)
    print(f"[{ALGORITHM_NAME} GCS] Waiting for drone connection on {GCS_HOST}:{PORT_KEY_EXCHANGE}")
    try:
        while True:
            conn, addr = server_sock.accept()
            print(f"[{ALGORITHM_NAME} GCS] Connection from {addr}")
            try:
                import oqs.oqs as oqs
                kem = oqs.KeyEncapsulation("ML-KEM-768")
                kyber_public = kem.generate_keypair()
                _ = kem.export_secret_key()
                _send_with_len(conn, kyber_public)
                ciphertext = _recv_with_len(conn)
                ss = kem.decap_secret(ciphertext)
                aes_key = hashlib.sha256(ss).digest()
                global cipher_suite
                cipher_suite = AESGCM(aes_key)
                # Receive drone signature public key, then send ours
                global drone_public_key
                drone_public_key = _recv_with_len(conn)
                _send_with_len(conn, sig_public_key)
                print(f"[{ALGORITHM_NAME} GCS] Key exchange completed with {addr}")
                conn.close()
                break
            except Exception as e:
                print(f"[{ALGORITHM_NAME} GCS] Handshake failed for {addr}: {e}. Waiting for next connection...")
                try:
                    conn.close()
                except Exception:
                    pass
                continue
    finally:
        server_sock.close()

def sign_message(message: bytes) -> bytes:
    try:
        return dilithium.sign(message)
    except Exception as e:
        print(f"[{ALGORITHM_NAME} GCS] Signing failed: {e}")
        return None

def verify_signature(message: bytes, signature: bytes, public_key: bytes) -> bool:
    try:
        return dilithium.verify(message, signature, public_key)
    except Exception as e:
        print(f"[{ALGORITHM_NAME} GCS] Signature verification failed: {e}")
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
        print(f"[{ALGORITHM_NAME} GCS] Decryption failed: {e}")
        return None

def commands_to_drone_thread():
    """Thread 1: Sign and encrypt outgoing commands from GCS applications to drone"""
    # Listen for plaintext commands from GCS applications
    listen_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listen_sock.bind((GCS_HOST, PORT_GCS_LISTEN_PLAINTEXT_CMD))
    
    # Socket to send signed+encrypted commands to drone
    send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    print(f"[{ALGORITHM_NAME} GCS] Command signing thread started")
    print(f"[{ALGORITHM_NAME} GCS] Listening for plaintext commands on {GCS_HOST}:{PORT_GCS_LISTEN_PLAINTEXT_CMD}")
    print(f"[{ALGORITHM_NAME} GCS] Forwarding signed+encrypted commands to {DRONE_HOST}:{PORT_DRONE_LISTEN_ENCRYPTED_CMD}")
    
    while True:
        try:
            # Receive plaintext command
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
            
            # Forward to drone
            send_sock.sendto(encrypted, (DRONE_HOST, PORT_DRONE_LISTEN_ENCRYPTED_CMD))
            
        except Exception as e:
            print(f"[{ALGORITHM_NAME} GCS] Command signing error: {e}")

def telemetry_from_drone_thread():
    """Thread 2: Decrypt and verify incoming telemetry from drone to GCS applications"""
    # Listen for encrypted telemetry from drone
    listen_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listen_sock.bind((GCS_HOST, PORT_GCS_LISTEN_ENCRYPTED_TLM))
    
    # Socket to send verified plaintext telemetry to GCS applications
    send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    print(f"[{ALGORITHM_NAME} GCS] Telemetry verification thread started")
    print(f"[{ALGORITHM_NAME} GCS] Listening for encrypted telemetry on {GCS_HOST}:{PORT_GCS_LISTEN_ENCRYPTED_TLM}")
    print(f"[{ALGORITHM_NAME} GCS] Forwarding verified telemetry to {GCS_HOST}:{PORT_GCS_FORWARD_DECRYPTED_TLM}")
    
    while True:
        try:
            # Receive encrypted telemetry
            encrypted, addr = listen_sock.recvfrom(65535)
            
            # Decrypt message
            decrypted = decrypt_message(encrypted)
            if decrypted is None:
                continue
            
            # Parse signed message
            if not decrypted.startswith(SIGNATURE_MARKER):
                print(f"[{ALGORITHM_NAME} GCS] Invalid message format")
                continue
            
            # Extract signature length
            sig_len = int.from_bytes(decrypted[len(SIGNATURE_MARKER):len(SIGNATURE_MARKER)+4], 'big')
            
            # Extract signature
            sig_start = len(SIGNATURE_MARKER) + 4
            signature = decrypted[sig_start:sig_start + sig_len]
            
            # Extract message
            msg_start = sig_start + sig_len + len(MESSAGE_MARKER)
            if decrypted[sig_start + sig_len:msg_start] != MESSAGE_MARKER:
                print(f"[{ALGORITHM_NAME} GCS] Invalid message marker")
                continue
            
            plaintext = decrypted[msg_start:]
            
            # Verify signature
            if verify_signature(plaintext, signature, drone_public_key):
                # Forward verified message to GCS application
                send_sock.sendto(plaintext, (GCS_HOST, PORT_GCS_FORWARD_DECRYPTED_TLM))
            else:
                print(f"[{ALGORITHM_NAME} GCS] Signature verification failed - message rejected")
            
        except Exception as e:
            print(f"[{ALGORITHM_NAME} GCS] Telemetry verification error: {e}")

def main():
    print(f"=== {ALGORITHM_NAME} GCS Proxy Starting ===")
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
        t1 = threading.Thread(target=commands_to_drone_thread, daemon=True)
        t2 = threading.Thread(target=telemetry_from_drone_thread, daemon=True)
        
        t1.start()
        t2.start()
        
        print(f"[{ALGORITHM_NAME} GCS] All threads started successfully")
        print(f"[{ALGORITHM_NAME} GCS] Proxy operational - Press Ctrl+C to stop\n")
        
        # Keep main thread alive
        while True:
            time.sleep(1)
            
    except KeyboardInterrupt:
        print(f"\n[{ALGORITHM_NAME} GCS] Shutting down...")
    except Exception as e:
        print(f"[{ALGORITHM_NAME} GCS] Critical error: {e}")

if __name__ == "__main__":
    main()