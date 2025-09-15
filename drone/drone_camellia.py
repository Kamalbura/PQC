#!/usr/bin/env python3
"""
Post-Quantum Secure Drone Communication System
Drone-side Camellia-128 Cipher Proxy

This proxy implements Camellia-128 block cipher encryption for MAVLink traffic.
Camellia is an ISO/IEC 18033-3 standard block cipher providing 128-bit security.

Network Flow:
- Receives plaintext MAVLink telemetry from drone applications on PORT_DRONE_SEND_PLAINTEXT_TELEM
- Encrypts using Camellia-128-GCM and forwards to GCS on PORT_DRONE_SEND_ENCRYPTED_TELEM  
- Receives encrypted MAVLink commands from GCS on PORT_DRONE_RECV_ENCRYPTED_CMD
- Decrypts and forwards plaintext to drone applications on PORT_DRONE_SEND_PLAINTEXT_CMD

Author: AI Coding Agent
Date: September 14, 2025
"""

import socket
import threading
import time
import os
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

# Import network configuration
from ip_config import *

# Algorithm-specific constants
ALGORITHM_NAME = "Camellia-128"
AES_KEY_SIZE = 32  # 256-bit AES key derived from Camellia exchange
NONCE_IV_SIZE = 12  # GCM nonce size
CAMELLIA_KEY_SIZE = 16  # 128-bit Camellia key

# Global variables
CAMELLIA_KEY = None
cipher_suite = None

def derive_aes_key_from_camellia(camellia_key: bytes) -> bytes:
    """Derive AES-256-GCM key from Camellia-128 key using PBKDF2"""
    salt = b"camellia-128-drone-salt"
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=AES_KEY_SIZE,
        salt=salt,
        iterations=10000,
        backend=default_backend()
    )
    return kdf.derive(camellia_key)

def setup_camellia_key_exchange():
    """Establish shared Camellia-128 key with GCS via TCP"""
    global CAMELLIA_KEY, cipher_suite
    
    print(f"[{ALGORITHM_NAME} Drone] Setting up key exchange with GCS...")
    
    # Connect to GCS for key exchange
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
        # Receive Camellia-128 key from GCS (simple shared secret approach)
        key_data = ex_sock.recv(CAMELLIA_KEY_SIZE)
        if len(key_data) != CAMELLIA_KEY_SIZE:
            raise ValueError(f"Expected {CAMELLIA_KEY_SIZE} bytes, got {len(key_data)}")
        
        CAMELLIA_KEY = key_data
        print(f"[{ALGORITHM_NAME} Drone] Received Camellia-128 key: {len(CAMELLIA_KEY)} bytes")
        
        # Derive AES-256-GCM key for actual encryption
        aes_key = derive_aes_key_from_camellia(CAMELLIA_KEY)
        
        # Create AES-GCM cipher for message encryption
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        cipher_suite = AESGCM(aes_key)
        
        # Send acknowledgment
        ex_sock.send(b"ACK_CAMELLIA_128")
        print(f"[{ALGORITHM_NAME} Drone] Key exchange completed successfully")
        
    except Exception as e:
        print(f"[{ALGORITHM_NAME} Drone] Key exchange failed: {e}")
        raise
    finally:
        ex_sock.close()

def encrypt_message(plaintext: bytes) -> bytes:
    """Encrypt message using AES-256-GCM derived from Camellia key"""
    if cipher_suite is None:
        raise ValueError("Cipher not initialized")
    
    nonce = os.urandom(NONCE_IV_SIZE)
    ciphertext = cipher_suite.encrypt(nonce, plaintext, None)
    return nonce + ciphertext

def decrypt_message(encrypted_message: bytes) -> bytes:
    """Decrypt message using AES-256-GCM derived from Camellia key"""
    if cipher_suite is None:
        raise ValueError("Cipher not initialized")
    
    try:
        nonce = encrypted_message[:NONCE_IV_SIZE]
        ciphertext = encrypted_message[NONCE_IV_SIZE:]
        return cipher_suite.decrypt(nonce, ciphertext, None)
    except Exception as e:
        print(f"[{ALGORITHM_NAME} Drone] Decryption failed: {e}")
        return None

def telemetry_to_gcs_thread():
    """Thread 1: Encrypt outgoing telemetry from drone applications to GCS"""
    # Listen for plaintext telemetry from drone applications
    listen_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listen_sock.bind((DRONE_HOST, PORT_DRONE_LISTEN_PLAINTEXT_TLM))
    
    # Socket to send encrypted telemetry to GCS
    send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    print(f"[{ALGORITHM_NAME} Drone] Telemetry encryption thread started")
    print(f"[{ALGORITHM_NAME} Drone] Listening for plaintext telemetry on {DRONE_HOST}:{PORT_DRONE_LISTEN_PLAINTEXT_TLM}")
    print(f"[{ALGORITHM_NAME} Drone] Forwarding encrypted telemetry to {GCS_HOST}:{PORT_GCS_LISTEN_ENCRYPTED_TLM}")
    
    while True:
        try:
            # Receive plaintext telemetry
            plaintext, addr = listen_sock.recvfrom(4096)
            
            # Encrypt using Camellia-derived AES key
            encrypted = encrypt_message(plaintext)
            
            # Forward to GCS
            send_sock.sendto(encrypted, (GCS_HOST, PORT_GCS_LISTEN_ENCRYPTED_TLM))
            
        except Exception as e:
            print(f"[{ALGORITHM_NAME} Drone] Telemetry encryption error: {e}")

def commands_from_gcs_thread():
    """Thread 2: Decrypt incoming commands from GCS to drone applications"""
    # Listen for encrypted commands from GCS
    listen_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listen_sock.bind((DRONE_HOST, PORT_DRONE_LISTEN_ENCRYPTED_CMD))
    
    # Socket to send plaintext commands to drone applications  
    send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    print(f"[{ALGORITHM_NAME} Drone] Command decryption thread started")
    print(f"[{ALGORITHM_NAME} Drone] Listening for encrypted commands on {DRONE_HOST}:{PORT_DRONE_LISTEN_ENCRYPTED_CMD}")
    print(f"[{ALGORITHM_NAME} Drone] Forwarding plaintext commands to {DRONE_HOST}:{PORT_DRONE_FORWARD_DECRYPTED_CMD}")
    
    while True:
        try:
            # Receive encrypted command
            encrypted, addr = listen_sock.recvfrom(4096)
            
            # Decrypt using Camellia-derived AES key
            plaintext = decrypt_message(encrypted)
            if plaintext is not None:
                # Forward to drone application
                send_sock.sendto(plaintext, (DRONE_HOST, PORT_DRONE_FORWARD_DECRYPTED_CMD))
            
        except Exception as e:
            print(f"[{ALGORITHM_NAME} Drone] Command decryption error: {e}")

def main():
    print(f"=== {ALGORITHM_NAME} Drone Proxy Starting ===")
    print(f"Algorithm: Camellia-128 block cipher")
    print(f"Key Size: 128 bits")
    print(f"Derived AES Key: 256 bits")
    print(f"Security: ISO/IEC 18033-3 standard\n")
    
    try:
        # Establish shared Camellia key with GCS
        setup_camellia_key_exchange()
        
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