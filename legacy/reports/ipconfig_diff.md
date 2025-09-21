# IP Configuration Consistency Analysis

## Files Analyzed
- `drone/ip_config.py`
- `gcs/ip_config.py`

## Configuration Differences

### Host Addresses
**Drone Config:**
```python
GCS_HOST = "127.0.0.1"    # Localhost for single-machine testing
DRONE_HOST = "127.0.0.1"  # Localhost for single-machine testing
```

**GCS Config:**
```python
# Updated 2023-09-13 GCS_HOST = "192.168.0.104"
GCS_HOST = "127.0.0.1"    # Localhost for single-machine testing
# Updated 2023-09-13 DRONE_HOST = "192.168.0.101" 
DRONE_HOST = "127.0.0.1"  # Localhost for single-machine testing
```

**Issues:**
- GCS config contains commented-out production IPs
- Both files hardcode localhost addresses
- No environment-based configuration

### Algorithm Mapping
**Drone Config:** Missing algorithm mapping
**GCS Config:** Contains algorithm mapping (lines 45-55)
```python
ALGORITHM_MAP = {
    "c1": "ascon",      # ASCON-128 AEAD (NIST SP 800-232)
    "c2": "speck",      # SPECK-128/128 (NSA lightweight)
    "c3": "camellia",   # Camellia-128 (ISO standard)
    "c4": "hight",      # HIGHT (Korean standard)
    "c5": "dilithium",  # Dilithium (NIST FIPS 204)
    "c6": "kyber",      # Kyber (NIST FIPS 203)
    "c7": "sphincs",    # SPHINCS+ (NIST Round 3)
    "c8": "falcon"      # Falcon (NIST Round 3)
}
```

### Security Issues in Both Files
1. **Command Injection Risk** - `update_hosts_persistent()` uses unsafe regex
2. **No Input Validation** - Host parameters not validated
3. **Non-atomic File Operations** - Risk of corruption during updates

## Recommended Canonical Configuration

```python
# config/ip_config.py (canonical version)
import os
from typing import Optional, List
import ipaddress

# Environment-based configuration
GCS_HOST = os.getenv("GCS_HOST", "127.0.0.1")
DRONE_HOST = os.getenv("DRONE_HOST", "127.0.0.1")
DRONE_ID = os.getenv("DRONE_ID", "drone1")

# Port configuration (standardized)
PORT_KEY_EXCHANGE = 5800
PORT_GCS_LISTEN_PLAINTEXT_CMD = 5810
PORT_DRONE_LISTEN_ENCRYPTED_CMD = 5811
PORT_DRONE_FORWARD_DECRYPTED_CMD = 5812
PORT_DRONE_LISTEN_PLAINTEXT_TLM = 5820
PORT_GCS_LISTEN_ENCRYPTED_TLM = 5821
PORT_GCS_FORWARD_DECRYPTED_TLM = 5822

# Cryptographic constants
NONCE_IV_SIZE = 12

# Algorithm mapping (NIST canonical names)
ALGORITHM_MAP = {
    "c1": "ascon-128",
    "c2": "speck-128",
    "c3": "camellia-128", 
    "c4": "hight",
    "c5": "ML-DSA-44",     # Dilithium2 → ML-DSA-44
    "c6": "ML-KEM-768",    # Kyber768 → ML-KEM-768
    "c7": "SPHINCS+-SHA2-128f-simple",
    "c8": "Falcon-512"
}

def validate_host(host: str) -> bool:
    """Validate host parameter to prevent injection."""
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        # Basic hostname validation
        if len(host) > 253 or not host:
            return False
        allowed = set('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-')
        return all(c in allowed for c in host)

def update_hosts_secure(new_gcs: Optional[str] = None, new_drone: Optional[str] = None) -> List[str]:
    """Secure host update with validation and atomic operations."""
    changes = []
    
    if new_gcs and validate_host(new_gcs):
        os.environ["GCS_HOST"] = new_gcs
        changes.append(f"GCS_HOST->{new_gcs}")
    
    if new_drone and validate_host(new_drone):
        os.environ["DRONE_HOST"] = new_drone
        changes.append(f"DRONE_HOST->{new_drone}")
    
    return changes
```
