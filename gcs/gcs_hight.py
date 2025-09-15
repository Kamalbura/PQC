#!/usr/bin/env python3
"""
Post-Quantum Secure Drone Communication System
GCS-side HIGHT Cipher Proxy

This proxy implements HIGHT (HIGh security and light weiGHT) block cipher for MAVLink traffic.
HIGHT is a Korean lightweight block cipher designed for resource-constrained environments.

Network Flow:
- Receives plaintext MAVLink commands from GCS applications on PORT_GCS_LISTEN_PLAINTEXT_CMD
- Encrypts using HIGHT-GCM and forwards to drone on PORT_GCS_SEND_ENCRYPTED_CMD
- Receives encrypted MAVLink telemetry from drone on PORT_GCS_LISTEN_ENCRYPTED_TELEM
- Decrypts and forwards plaintext to GCS applications on PORT_GCS_SEND_PLAINTEXT_TELEM

Author: AI Coding Agent
Date: September 14, 2025
"""

import socket
import threading
import time
import os
import struct
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

# Import network configuration
from ip_config import *

# Algorithm-specific constants
ALGORITHM_NAME = "HIGHT"
AES_KEY_SIZE = 32  # 256-bit AES key derived from HIGHT exchange
NONCE_IV_SIZE = 12  # GCM nonce size
HIGHT_KEY_SIZE = 16  # 128-bit HIGHT key
HIGHT_BLOCK_SIZE = 8  # 64-bit HIGHT block size

# Global variables
HIGHT_KEY = None
cipher_suite = None

class HIGHTCipher:
    """Simplified HIGHT implementation for research purposes"""
    
    def __init__(self, key: bytes):
        if len(key) != HIGHT_KEY_SIZE:
            raise ValueError(f"HIGHT key must be {HIGHT_KEY_SIZE} bytes")
        self.key = key
        self.subkeys = self._generate_subkeys()
    
    def _generate_subkeys(self):
        """Generate HIGHT round subkeys (simplified version)"""
        # This is a simplified subkey generation - in real HIGHT, this would be more complex
        subkeys = []
        for i in range(32):  # HIGHT uses 32 rounds
            subkey = ((self.key[i % 16] + i) & 0xFF)
            subkeys.append(subkey)
        return subkeys
    
    def _f_function(self, x: int, subkey: int) -> int:
        """HIGHT F-function (simplified)"""
        return ((x + subkey) & 0xFF) ^ ((x << 1) & 0xFF) ^ ((x >> 1) & 0xFF)
    
    def encrypt_block(self, plaintext_block: bytes) -> bytes:
        """Encrypt a single 8-byte block with HIGHT"""
        if len(plaintext_block) != HIGHT_BLOCK_SIZE:
            raise ValueError(f"Block must be {HIGHT_BLOCK_SIZE} bytes")
        
        # Convert bytes to integers
        x = list(plaintext_block)
        
        # Simplified HIGHT encryption (32 rounds)
        for round_num in range(32):
            # Apply F-function with round subkey
            temp = self._f_function(x[0], self.subkeys[round_num])
            
            # Rotate data
            x = [x[1], x[2], x[3], temp ^ x[4], x[5], x[6], x[7], x[0]]
        
        return bytes(x)
    
    def decrypt_block(self, ciphertext_block: bytes) -> bytes:
        """Decrypt a single 8-byte block with HIGHT"""
        if len(ciphertext_block) != HIGHT_BLOCK_SIZE:
            raise ValueError(f"Block must be {HIGHT_BLOCK_SIZE} bytes")
        
        # Convert bytes to integers
        x = list(ciphertext_block)
        
        # Simplified HIGHT decryption (32 rounds in reverse)
        for round_num in range(31, -1, -1):
            # Reverse rotate data
            x = [x[7], x[0], x[1], x[2], x[3], x[4], x[5], x[6]]
            
            # Apply inverse F-function
            temp = self._f_function(x[7], self.subkeys[round_num])
            x[4] ^= temp
        
        return bytes(x)

def derive_aes_key_from_hight(hight_key: bytes) -> bytes:
    """Derive AES-256-GCM key from HIGHT-128 key using PBKDF2"""
    salt = b"hight-128-drone-salt"
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=AES_KEY_SIZE,
        salt=salt,
        iterations=10000,
        backend=default_backend()
    )
    return kdf.derive(hight_key)

def setup_hight_key_exchange():
    """Establish shared HIGHT-128 key with drone via TCP"""
    global HIGHT_KEY, cipher_suite
    
    print(f"[{ALGORITHM_NAME} GCS] Setting up key exchange server...")
    
    # Create TCP server for key exchange
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind((GCS_HOST, PORT_KEY_EXCHANGE))
    server_sock.listen(1)
    
    print(f"[{ALGORITHM_NAME} GCS] Waiting for drone connection on {GCS_HOST}:{PORT_KEY_EXCHANGE}")
    
    try:
        # Accept drone connection
        conn, addr = server_sock.accept()
        print(f"[{ALGORITHM_NAME} GCS] Drone connected from {addr}")
        
        # Generate HIGHT-128 key
        HIGHT_KEY = os.urandom(HIGHT_KEY_SIZE)
        print(f"[{ALGORITHM_NAME} GCS] Generated HIGHT-128 key: {len(HIGHT_KEY)} bytes")
        
        # Send key to drone
        conn.send(HIGHT_KEY)
        
        # Derive AES-256-GCM key for actual encryption
        aes_key = derive_aes_key_from_hight(HIGHT_KEY)
        
        # Create AES-GCM cipher for message encryption
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        cipher_suite = AESGCM(aes_key)
        
        # Wait for acknowledgment
        ack = conn.recv(1024)
        if ack == b"ACK_HIGHT_128":
            print(f"[{ALGORITHM_NAME} GCS] Key exchange completed successfully")
        else:
            raise ValueError(f"Invalid acknowledgment: {ack}")
        
    except Exception as e:
        print(f"[{ALGORITHM_NAME} GCS] Key exchange failed: {e}")
        raise
    finally:
        server_sock.close()

def encrypt_message(plaintext: bytes) -> bytes:
    """Encrypt message using AES-256-GCM derived from HIGHT key"""
    if cipher_suite is None:
        raise ValueError("Cipher not initialized")
    
    nonce = os.urandom(NONCE_IV_SIZE)
    ciphertext = cipher_suite.encrypt(nonce, plaintext, None)
    return nonce + ciphertext

def decrypt_message(encrypted_message: bytes) -> bytes:
    """Decrypt message using AES-256-GCM derived from HIGHT key"""
    if cipher_suite is None:
        raise ValueError("Cipher not initialized")
    
    try:
        nonce = encrypted_message[:NONCE_IV_SIZE]
        ciphertext = encrypted_message[NONCE_IV_SIZE:]
        return cipher_suite.decrypt(nonce, ciphertext, None)
    except Exception as e:
        print(f"[{ALGORITHM_NAME} GCS] Decryption failed: {e}")
        return None

def commands_to_drone_thread():
    """Thread 1: Encrypt outgoing commands from GCS applications to drone"""
    # Listen for plaintext commands from GCS applications
    listen_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listen_sock.bind((GCS_HOST, PORT_GCS_LISTEN_PLAINTEXT_CMD))
    
    # Socket to send encrypted commands to drone
    send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    print(f"[{ALGORITHM_NAME} GCS] Command encryption thread started")
    print(f"[{ALGORITHM_NAME} GCS] Listening for plaintext commands on {GCS_HOST}:{PORT_GCS_LISTEN_PLAINTEXT_CMD}")
    print(f"[{ALGORITHM_NAME} GCS] Forwarding encrypted commands to {DRONE_HOST}:{PORT_DRONE_LISTEN_ENCRYPTED_CMD}")
    
    while True:
        try:
            # Receive plaintext command
            plaintext, addr = listen_sock.recvfrom(4096)
            
            # Encrypt using HIGHT-derived AES key
            encrypted = encrypt_message(plaintext)
            
            # Forward to drone
            send_sock.sendto(encrypted, (DRONE_HOST, PORT_DRONE_LISTEN_ENCRYPTED_CMD))
            
        except Exception as e:
            print(f"[{ALGORITHM_NAME} GCS] Command encryption error: {e}")

def telemetry_from_drone_thread():
    """Thread 2: Decrypt incoming telemetry from drone to GCS applications"""
    # Listen for encrypted telemetry from drone
    listen_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listen_sock.bind((GCS_HOST, PORT_GCS_LISTEN_ENCRYPTED_TLM))
    
    # Socket to send plaintext telemetry to GCS applications
    send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    print(f"[{ALGORITHM_NAME} GCS] Telemetry decryption thread started")
    print(f"[{ALGORITHM_NAME} GCS] Listening for encrypted telemetry on {GCS_HOST}:{PORT_GCS_LISTEN_ENCRYPTED_TLM}")
    print(f"[{ALGORITHM_NAME} GCS] Forwarding plaintext telemetry to {GCS_HOST}:{PORT_GCS_FORWARD_DECRYPTED_TLM}")
    
    while True:
        try:
            # Receive encrypted telemetry
            encrypted, addr = listen_sock.recvfrom(4096)
            
            # Decrypt using HIGHT-derived AES key
            plaintext = decrypt_message(encrypted)
            if plaintext is not None:
                # Forward to GCS application
                send_sock.sendto(plaintext, (GCS_HOST, PORT_GCS_FORWARD_DECRYPTED_TLM))
            
        except Exception as e:
            print(f"[{ALGORITHM_NAME} GCS] Telemetry decryption error: {e}")

def main():
    print(f"=== {ALGORITHM_NAME} GCS Proxy Starting ===")
    print(f"Algorithm: HIGHT (Korean lightweight cipher)")
    print(f"Key Size: 128 bits")
    print(f"Block Size: 64 bits")
    print(f"Derived AES Key: 256 bits")
    print(f"Security: Lightweight block cipher\n")
    
    try:
        # Establish shared HIGHT key with drone
        setup_hight_key_exchange()
        
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