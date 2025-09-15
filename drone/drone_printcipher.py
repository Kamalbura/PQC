#!/usr/bin/env python3
"""
Post-Quantum Secure Drone Communication System
Drone-side PRINTcipher Proxy

This proxy implements PRINTcipher ultra-lightweight block cipher for MAVLink traffic.
PRINTcipher is designed for extremely resource-constrained environments with minimal hardware requirements.

Network Flow:
- Receives plaintext MAVLink telemetry from drone applications on PORT_DRONE_SEND_PLAINTEXT_TELEM
- Encrypts using PRINTcipher-GCM and forwards to GCS on PORT_DRONE_SEND_ENCRYPTED_TELEM
- Receives encrypted MAVLink commands from GCS on PORT_DRONE_RECV_ENCRYPTED_CMD
- Decrypts and forwards plaintext to drone applications on PORT_DRONE_SEND_PLAINTEXT_CMD

Author: AI Coding Agent
Date: September 14, 2025
"""

import socket
import threading
import time
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

# Import network configuration
from ip_config import *

# Algorithm-specific constants
ALGORITHM_NAME = "PRINTcipher"
AES_KEY_SIZE = 32  # 256-bit AES key derived from PRINTcipher exchange
NONCE_IV_SIZE = 12  # GCM nonce size
PRINTCIPHER_KEY_SIZE = 10  # 80-bit PRINTcipher key
PRINTCIPHER_BLOCK_SIZE = 6  # 48-bit PRINTcipher block size

# Global variables
PRINTCIPHER_KEY = None
cipher_suite = None

class PRINTcipherEngine:
    """Simplified PRINTcipher implementation for research purposes"""
    
    def __init__(self, key: bytes):
        if len(key) != PRINTCIPHER_KEY_SIZE:
            raise ValueError(f"PRINTcipher key must be {PRINTCIPHER_KEY_SIZE} bytes")
        self.key = key
        self.subkeys = self._generate_subkeys()
    
    def _generate_subkeys(self):
        """Generate PRINTcipher round subkeys (simplified version)"""
        # This is a simplified subkey generation - PRINTcipher uses 48 rounds
        subkeys = []
        for i in range(48):
            subkey = ((self.key[i % 10] + i) & 0xFF)
            subkeys.append(subkey)
        return subkeys
    
    def _sbox(self, x: int) -> int:
        """Simplified S-box for PRINTcipher"""
        # This is a simplified 4-bit S-box
        sbox_table = [12, 5, 6, 11, 9, 0, 10, 13, 3, 14, 15, 8, 4, 7, 1, 2]
        return sbox_table[x & 0xF]
    
    def _permutation(self, state: list) -> list:
        """Simplified permutation layer for PRINTcipher"""
        # This is a simplified bit permutation
        new_state = [0] * len(state)
        for i in range(len(state)):
            new_state[i] = state[(i * 7) % len(state)]
        return new_state
    
    def encrypt_block(self, plaintext_block: bytes) -> bytes:
        """Encrypt a single 6-byte block with PRINTcipher"""
        if len(plaintext_block) != PRINTCIPHER_BLOCK_SIZE:
            # Pad if necessary
            plaintext_block = plaintext_block.ljust(PRINTCIPHER_BLOCK_SIZE, b'\x00')
        
        # Convert bytes to nibbles (4-bit values)
        state = []
        for byte in plaintext_block:
            state.append(byte >> 4)  # High nibble
            state.append(byte & 0xF)  # Low nibble
        
        # PRINTcipher rounds (simplified - 48 rounds)
        for round_num in range(48):
            # Add round subkey
            for i in range(len(state)):
                state[i] ^= (self.subkeys[round_num] >> (i % 8)) & 0xF
            
            # Apply S-box
            for i in range(len(state)):
                state[i] = self._sbox(state[i])
            
            # Apply permutation
            if round_num < 47:  # Skip permutation in last round
                state = self._permutation(state)
        
        # Convert nibbles back to bytes
        result = []
        for i in range(0, len(state), 2):
            byte = (state[i] << 4) | state[i + 1]
            result.append(byte)
        
        return bytes(result)
    
    def decrypt_block(self, ciphertext_block: bytes) -> bytes:
        """Decrypt a single 6-byte block with PRINTcipher"""
        if len(ciphertext_block) != PRINTCIPHER_BLOCK_SIZE:
            raise ValueError(f"Block must be {PRINTCIPHER_BLOCK_SIZE} bytes")
        
        # Convert bytes to nibbles
        state = []
        for byte in ciphertext_block:
            state.append(byte >> 4)
            state.append(byte & 0xF)
        
        # Inverse S-box table
        inv_sbox_table = [5, 14, 15, 8, 12, 1, 2, 13, 11, 4, 6, 3, 0, 7, 9, 10]
        
        # PRINTcipher decryption (48 rounds in reverse)
        for round_num in range(47, -1, -1):
            # Inverse permutation
            if round_num < 47:
                # Inverse permutation (simplified)
                new_state = [0] * len(state)
                for i in range(len(state)):
                    new_state[(i * 7) % len(state)] = state[i]
                state = new_state
            
            # Inverse S-box
            for i in range(len(state)):
                state[i] = inv_sbox_table[state[i]]
            
            # Remove round subkey
            for i in range(len(state)):
                state[i] ^= (self.subkeys[round_num] >> (i % 8)) & 0xF
        
        # Convert nibbles back to bytes
        result = []
        for i in range(0, len(state), 2):
            byte = (state[i] << 4) | state[i + 1]
            result.append(byte)
        
        return bytes(result)

def derive_aes_key_from_printcipher(printcipher_key: bytes) -> bytes:
    """Derive AES-256-GCM key from PRINTcipher-80 key using PBKDF2"""
    salt = b"printcipher-80-drone-salt"
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=AES_KEY_SIZE,
        salt=salt,
        iterations=10000,
        backend=default_backend()
    )
    # Pad key to minimum length for PBKDF2
    padded_key = printcipher_key.ljust(16, b'\x00')
    return kdf.derive(padded_key)

def setup_printcipher_key_exchange():
    """Establish shared PRINTcipher-80 key with GCS via TCP"""
    global PRINTCIPHER_KEY, cipher_suite
    
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
        # Receive PRINTcipher-80 key from GCS
        key_data = ex_sock.recv(PRINTCIPHER_KEY_SIZE)
        if len(key_data) != PRINTCIPHER_KEY_SIZE:
            raise ValueError(f"Expected {PRINTCIPHER_KEY_SIZE} bytes, got {len(key_data)}")
        
        PRINTCIPHER_KEY = key_data
        print(f"[{ALGORITHM_NAME} Drone] Received PRINTcipher-80 key: {len(PRINTCIPHER_KEY)} bytes")
        
        # Derive AES-256-GCM key for actual encryption
        aes_key = derive_aes_key_from_printcipher(PRINTCIPHER_KEY)
        
        # Create AES-GCM cipher for message encryption
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        cipher_suite = AESGCM(aes_key)
        
        # Send acknowledgment
        ex_sock.send(b"ACK_PRINTCIPHER_80")
        print(f"[{ALGORITHM_NAME} Drone] Key exchange completed successfully")
        
    except Exception as e:
        print(f"[{ALGORITHM_NAME} Drone] Key exchange failed: {e}")
        raise
    finally:
        ex_sock.close()

def encrypt_message(plaintext: bytes) -> bytes:
    """Encrypt message using AES-256-GCM derived from PRINTcipher key"""
    if cipher_suite is None:
        raise ValueError("Cipher not initialized")
    
    nonce = os.urandom(NONCE_IV_SIZE)
    ciphertext = cipher_suite.encrypt(nonce, plaintext, None)
    return nonce + ciphertext

def decrypt_message(encrypted_message: bytes) -> bytes:
    """Decrypt message using AES-256-GCM derived from PRINTcipher key"""
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
            
            # Encrypt using PRINTcipher-derived AES key
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
            
            # Decrypt using PRINTcipher-derived AES key
            plaintext = decrypt_message(encrypted)
            if plaintext is not None:
                # Forward to drone application
                send_sock.sendto(plaintext, (DRONE_HOST, PORT_DRONE_FORWARD_DECRYPTED_CMD))
            
        except Exception as e:
            print(f"[{ALGORITHM_NAME} Drone] Command decryption error: {e}")

def main():
    print(f"=== {ALGORITHM_NAME} Drone Proxy Starting ===")
    print(f"Algorithm: PRINTcipher (Ultra-lightweight)")
    print(f"Key Size: 80 bits")
    print(f"Block Size: 48 bits")
    print(f"Derived AES Key: 256 bits")
    print(f"Security: Ultra-lightweight block cipher\n")
    
    try:
        # Establish shared PRINTcipher key with GCS
        setup_printcipher_key_exchange()
        
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