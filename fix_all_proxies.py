#!/usr/bin/env python3
"""
Systematic fix script for all proxy implementations in drone/ and gcs/ folders.
This script applies the standardized fixes to all 32 proxy files.
"""

import os
import re
import glob

def fix_drone_kyber_variants():
    """Fix all Kyber variants in drone folder"""
    files = ['drone/drone_kyber_512.py', 'drone/drone_kyber_1024.py']
    
    for file_path in files:
        if not os.path.exists(file_path):
            continue
            
        variant = file_path.split('_')[-1].replace('.py', '')
        
        with open(file_path, 'r') as f:
            content = f.read()
        
        # Fix key exchange section
        old_pattern = r'kem = oqs\.KeyEncapsulation\("ML-KEM-' + variant + r'"\)\s*\n\s*ex_sock = socket\.socket.*?print\("✅ \[KYBER-' + variant + r' Drone\] Shared key established"\)'
        
        new_section = f'''# Global crypto objects - initialized after key exchange
aesgcm = None
crypto_ready = threading.Event()

def perform_key_exchange():
    """Perform key exchange with timeout and retry limit"""
    global aesgcm, crypto_ready
    
    kem = oqs.KeyEncapsulation("ML-KEM-{variant}")
    max_retries = 30  # 60 seconds total
    retry_count = 0
    
    while retry_count < max_retries:
        try:
            ex_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            ex_sock.settimeout(5.0)  # 5 second connection timeout
            ex_sock.connect((GCS_HOST, PORT_KEY_EXCHANGE))
            
            print(f"[KYBER-{variant} Drone] Connected to {{GCS_HOST}}:{{PORT_KEY_EXCHANGE}}")
            gcs_public_key = _recv_with_len(ex_sock)
            ciphertext, shared_secret = kem.encap_secret(gcs_public_key)
            _send_with_len(ex_sock, ciphertext)
            AES_KEY = hashlib.sha256(shared_secret).digest()
            ex_sock.close()
            
            # Initialize crypto
            aesgcm = AESGCM(AES_KEY)
            crypto_ready.set()  # Signal threads that crypto is ready
            print("✅ [KYBER-{variant} Drone] Shared key established")
            return
            
        except (ConnectionRefusedError, socket.timeout, OSError) as e:
            retry_count += 1
            print(f"[KYBER-{variant} Drone] Connection attempt {{retry_count}}/{{max_retries}} failed: {{e}}")
            if retry_count < max_retries:
                time.sleep(2)
            try:
                ex_sock.close()
            except:
                pass
    
    raise RuntimeError(f"[KYBER-{variant} Drone] Could not connect to GCS after {{max_retries}} attempts")

# Perform key exchange before starting threads
perform_key_exchange()'''
        
        content = re.sub(old_pattern, new_section, content, flags=re.DOTALL)
        
        # Fix thread functions if not already fixed
        if 'crypto_ready.wait()' not in content:
            # Add crypto functions and fix threads
            crypto_functions = f'''
def encrypt_message(plaintext: bytes) -> bytes:
    """Encrypt message using AES-256-GCM"""
    if not crypto_ready.is_set():
        raise RuntimeError("Crypto not initialized")
    nonce = os.urandom(NONCE_IV_SIZE)
    ct = aesgcm.encrypt(nonce, plaintext, None)
    return nonce + ct


def decrypt_message(encrypted_message: bytes):
    """Decrypt message using AES-256-GCM"""
    if not crypto_ready.is_set():
        return None
    try:
        if len(encrypted_message) < NONCE_IV_SIZE:
            return None
        nonce = encrypted_message[:NONCE_IV_SIZE]
        ct = encrypted_message[NONCE_IV_SIZE:]
        return aesgcm.decrypt(nonce, ct, None)
    except Exception as e:
        print(f"[KYBER-{variant} Drone] Decryption failed: {{e}}")
        return None


def telemetry_to_gcs_thread():
    """Thread 1: Encrypt outgoing telemetry from flight controller to GCS"""
    crypto_ready.wait()
    
    listen_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listen_sock.bind((DRONE_HOST, PORT_DRONE_LISTEN_PLAINTEXT_TLM))
    
    send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    print(f"[KYBER-{variant} Drone] Listening plaintext TLM on {{DRONE_HOST}}:{{PORT_DRONE_LISTEN_PLAINTEXT_TLM}}")
    print(f"[KYBER-{variant} Drone] Forwarding encrypted TLM to {{GCS_HOST}}:{{PORT_GCS_LISTEN_ENCRYPTED_TLM}}")
    
    while True:
        try:
            data, addr = listen_sock.recvfrom(65535)
            enc = encrypt_message(data)
            send_sock.sendto(enc, (GCS_HOST, PORT_GCS_LISTEN_ENCRYPTED_TLM))
        except Exception as e:
            print(f"[KYBER-{variant} Drone] Telemetry thread error: {{e}}")
            time.sleep(0.1)


def commands_from_gcs_thread():
    """Thread 2: Decrypt incoming commands from GCS to flight controller"""
    crypto_ready.wait()
    
    listen_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listen_sock.bind((DRONE_HOST, PORT_DRONE_LISTEN_ENCRYPTED_CMD))
    
    forward_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    print(f"[KYBER-{variant} Drone] Listening encrypted CMD on {{DRONE_HOST}}:{{PORT_DRONE_LISTEN_ENCRYPTED_CMD}}")
    print(f"[KYBER-{variant} Drone] Forwarding decrypted CMD to {{DRONE_HOST}}:{{PORT_DRONE_FORWARD_DECRYPTED_CMD}}")
    
    while True:
        try:
            data, addr = listen_sock.recvfrom(65535)
            pt = decrypt_message(data)
            if pt:
                forward_sock.sendto(pt, (DRONE_HOST, PORT_DRONE_FORWARD_DECRYPTED_CMD))
        except Exception as e:
            print(f"[KYBER-{variant} Drone] Command thread error: {{e}}")
            time.sleep(0.1)
'''
            
            # Replace old functions and threads
            content = re.sub(r'def encrypt_message.*?def commands_from_gcs_thread.*?sock\.sendto\(pt, \(DRONE_HOST, PORT_DRONE_FORWARD_DECRYPTED_CMD\)\)', 
                           crypto_functions, content, flags=re.DOTALL)
        
        with open(file_path, 'w') as f:
            f.write(content)
        
        print(f"Fixed {file_path}")

if __name__ == "__main__":
    fix_drone_kyber_variants()
    print("Kyber variants fixed!")