# Security Audit: drone/drone_ascon.py

## File Overview
Drone-side proxy for ASCON-128 AEAD with AES-GCM fallback mechanism.

## Functions and Classes

### Line 12-18: Import and Fallback Logic
- **CRITICAL**: Insecure fallback to AES-GCM without user notification
- **HIGH**: Silent algorithm substitution compromises security assumptions
- **MEDIUM**: Proper exception handling for missing dependencies

### Line 25-38: Key Exchange Setup
- **CRITICAL**: Insecure 16-byte key exchange over plain TCP (line 37)
- **CRITICAL**: No authentication or integrity protection for key material
- **HIGH**: Blocking connection without timeout protection
- **HIGH**: Pre-shared key model inappropriate for production use

### Line 40-48: Algorithm Selection Logic
- **HIGH**: Key expansion using SHA-256 without proper KDF (line 47)
- **MEDIUM**: Inconsistent nonce sizes between ASCON (16) and AES-GCM (12)
- **LOW**: Clear algorithm selection logging

### Line 51-74: Encryption/Decryption Functions
- **HIGH**: Different nonce sizes create implementation complexity (lines 53, 57)
- **HIGH**: Uses `os.urandom()` without entropy validation
- **MEDIUM**: Empty associated data in ASCON AEAD mode (line 54)
- **MEDIUM**: Silent failure on decryption errors (line 73)

### Line 77-85: `telemetry_to_gcs_thread()`
- **HIGH**: No bounds checking on UDP receive (line 82)
- **MEDIUM**: No error handling for encryption failures
- **LOW**: Standard UDP proxy pattern

### Line 87-96: `commands_from_gcs_thread()`
- **HIGH**: No bounds checking on UDP receive (line 92)
- **HIGH**: Silent failure on decryption (line 94-95)
- **MEDIUM**: No replay attack protection

### Line 98-105: Main Execution
- **MEDIUM**: Daemon threads without proper cleanup
- **LOW**: Simple main execution pattern

## Security Issues Summary
- **CRITICAL**: 3 issues (insecure key exchange, silent algorithm fallback)
- **HIGH**: 8 issues (key derivation, bounds checking, entropy)
- **MEDIUM**: 6 issues (nonce handling, error handling)
- **LOW**: 3 issues (minor implementation details)

## Recommendations
1. **NON-PRODUCTION**: Mark as disabled due to insecure key exchange
2. Implement proper authenticated key exchange protocol
3. Remove silent algorithm fallback mechanism
4. Use proper KDF for key derivation (HKDF-SHA256)
5. Standardize nonce sizes across algorithms
