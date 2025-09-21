# Security Audit: drone/drone_dilithium2.py

## File Overview
Post-quantum signature proxy using Dilithium2 (ML-DSA-44) with Kyber-768 key exchange.

## Functions and Classes

### Line 38-46: `setup_dilithium_and_kyber()`
- **CRITICAL**: Uses global variables for private keys (line 33-36)
- **CRITICAL**: No secure memory clearing after key generation
- **HIGH**: Missing error handling for key generation failures
- **MEDIUM**: Hardcoded algorithm name "Dilithium2" should use canonical "ML-DSA-44"

### Line 48-55: `_recv_exact()`
- **LOW**: Standard socket receive helper, no security issues

### Line 57-63: `_recv_with_len()` / `_send_with_len()`
- **HIGH**: No bounds checking on length prefix (line 58)
- **HIGH**: Potential integer overflow in length calculation
- **MEDIUM**: No timeout handling for blocking operations

### Line 65-94: `setup_key_exchange()`
- **CRITICAL**: Uses deprecated "ML-KEM-768" instead of canonical name
- **CRITICAL**: No mutual authentication during key exchange
- **CRITICAL**: Key exchange over unencrypted TCP connection
- **HIGH**: No replay protection or session management
- **HIGH**: Private keys transmitted without additional protection

### Line 96-101: `sign_message()`
- **CRITICAL**: Returns `None` on failure instead of raising exception
- **HIGH**: No input validation on message parameter
- **MEDIUM**: Missing constant-time implementation

### Line 103-109: `verify_signature()`
- **CRITICAL**: Returns `False` on exception, should distinguish verification failure from error
- **HIGH**: No input validation on signature/key parameters
- **MEDIUM**: Missing constant-time implementation

### Line 111-125: `encrypt_message()` / `decrypt_message()`
- **HIGH**: Uses `os.urandom()` without entropy validation
- **MEDIUM**: No associated data in AEAD mode
- **LOW**: Standard AES-GCM implementation

### Line 127-165: `telemetry_to_gcs_thread()`
- **HIGH**: No bounds checking on UDP receive (line 144)
- **HIGH**: Silent failure on signing errors (line 148-149)
- **MEDIUM**: No rate limiting or DoS protection

### Line 167-219: `commands_from_gcs_thread()`
- **HIGH**: No bounds checking on UDP receive (line 184)
- **HIGH**: Complex message parsing without validation (lines 192-209)
- **MEDIUM**: No replay attack protection

## Security Issues Summary
- **CRITICAL**: 6 issues (global key storage, insecure key exchange, error handling)
- **HIGH**: 9 issues (bounds checking, authentication, validation)
- **MEDIUM**: 6 issues (algorithm names, DoS protection)
- **LOW**: 2 issues (minor implementation details)

## Recommendations
1. Replace global key storage with secure key management
2. Implement mutual authentication for key exchange
3. Add proper input validation and bounds checking
4. Use canonical algorithm names from NIST standards
5. Implement constant-time cryptographic operations
