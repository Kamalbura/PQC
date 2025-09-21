# liboqs Mapping: Falcon Algorithms

## Repository Implementation → liboqs Reference Mapping

### Falcon-512
**Repository Files**: `drone_falcon512.py`, `gcs_falcon512.py`
**liboqs Algorithm Name**: `"Falcon-512"`
**Repository Usage**: `"Falcon-512"` ✓ CORRECT

#### Function Mappings:
- `falcon.generate_keypair()` → `oqs.Signature.generate_keypair()`
- `falcon.sign(message, secret_key)` → `oqs.Signature.sign(message)`
- `falcon.verify(message, signature, public_key)` → `oqs.Signature.verify(message, signature, public_key)`

#### Expected Parameters:
- Public Key Length: 897 bytes
- Secret Key Length: 1281 bytes
- Signature Length: ~690 bytes (variable)

### Falcon-1024
**Repository Files**: `drone_falcon1024.py`, `gcs_falcon1024.py`
**liboqs Algorithm Name**: `"Falcon-1024"`
**Repository Usage**: `"Falcon-1024"` ✓ CORRECT

#### Expected Parameters:
- Public Key Length: 1793 bytes
- Secret Key Length: 2305 bytes
- Signature Length: ~1330 bytes (variable)

## Critical Issues Found
1. **INCORRECT KEY EXCHANGE**: `drone_falcon512.py:79` uses deprecated `"Kyber768"` instead of `"ML-KEM-768"`
2. **INSECURE KEY HANDLING**: Private keys stored in global dictionary without secure memory management
3. **BUFFER OVERFLOW RISK**: Fixed 4096-byte receive buffers without bounds checking
4. **NO CONSTANT-TIME**: Missing side-channel protection in signature operations

## Security Parameters (NIST Levels)
- Falcon-512: NIST Security Level 1 (128-bit classical security)
- Falcon-1024: NIST Security Level 5 (256-bit classical security)

## Implementation Notes
- Falcon uses NTRU lattices and FFT-based operations
- Requires careful floating-point implementation for security
- Compact signatures but complex key generation
- Should use constant-time implementations to prevent timing attacks
