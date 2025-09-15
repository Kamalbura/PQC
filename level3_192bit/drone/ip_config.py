"""
NIST Security Level 3 (192-bit) - Network Configuration
Equivalent to AES-192 security level

Algorithms at this level:
- ML-KEM-768 (Key Encapsulation)
- ML-DSA-65 (Digital Signatures)
- SPHINCS+-SHA2-192f/s (Hash-based Signatures)
- SPHINCS+-Haraka-192f/s (Hash-based Signatures)
"""

# Network Configuration
GCS_HOST = "127.0.0.1"      # GCS (Ground Control Station) IP
DRONE_HOST = "127.0.0.1"    # Drone IP

# Key Exchange Port (TCP)
PORT_KEY_EXCHANGE = 5800

# Command Flow Ports (UDP) - GCS to Drone
PORT_GCS_LISTEN_PLAINTEXT_CMD = 5810       # GCS receives plaintext commands
PORT_GCS_SEND_ENCRYPTED_CMD = 5811         # GCS sends encrypted commands  
PORT_DRONE_FORWARD_DECRYPTED_CMD = 5812    # Drone forwards decrypted commands

# Telemetry Flow Ports (UDP) - Drone to GCS  
PORT_DRONE_LISTEN_PLAINTEXT_TLM = 5820     # Drone receives plaintext telemetry
PORT_DRONE_SEND_ENCRYPTED_TLM = 5821       # Drone sends encrypted telemetry
PORT_GCS_FORWARD_DECRYPTED_TLM = 5822      # GCS forwards decrypted telemetry

# Security Level Info
NIST_SECURITY_LEVEL = 3
EQUIVALENT_AES_BITS = 192
LEVEL_DESCRIPTION = "NIST Level 3 - Strong security, balanced performance"