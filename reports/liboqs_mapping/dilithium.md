# liboqs Mapping: Dilithium (ML-DSA) Algorithms

## Repository Implementation → liboqs Reference Mapping

### ML-DSA-44 (Dilithium2)
**Repository Files**: `drone_dilithium2.py`, `gcs_dilithium2.py`
**liboqs Algorithm Name**: `"ML-DSA-44"`
**Repository Usage**: `"Dilithium2"` ❌ INCORRECT (should be "ML-DSA-44")

#### Function Mappings:
- `dilithium.generate_keypair()` → `oqs.Signature.generate_keypair()`
- `dilithium.sign(message)` → `oqs.Signature.sign(message)`
- `dilithium.verify(message, signature, public_key)` → `oqs.Signature.verify(message, signature, public_key)`

#### Expected Parameters:
- Public Key Length: 1312 bytes
- Secret Key Length: 2528 bytes
- Signature Length: ~2420 bytes (variable)

### ML-DSA-65 (Dilithium3)
**Repository Files**: `drone_dilithium3.py`, `gcs_dilithium3.py`
**liboqs Algorithm Name**: `"ML-DSA-65"`
**Repository Usage**: `"Dilithium3"` ❌ INCORRECT

### ML-DSA-87 (Dilithium5)
**Repository Files**: `drone_dilithium5.py`, `gcs_dilithium5.py`
**liboqs Algorithm Name**: `"ML-DSA-87"`
**Repository Usage**: `"Dilithium5"` ❌ INCORRECT

## Security Parameters (NIST Levels)
- ML-DSA-44: NIST Security Level 2 (128-bit classical security)
- ML-DSA-65: NIST Security Level 3 (192-bit classical security)
- ML-DSA-87: NIST Security Level 5 (256-bit classical security)

## Critical Issues Found
1. All Dilithium implementations use deprecated algorithm names
2. Missing constant-time implementations for side-channel protection
3. Private keys stored in global variables without secure memory management
4. No proper error handling - returns None instead of raising exceptions

## Canonical Algorithm Names (NIST FIPS 204)
- `"ML-DSA-44"` (not "Dilithium2", "DILITHIUM_2", or "Dilithium-2")
- `"ML-DSA-65"` (not "Dilithium3", "DILITHIUM_3", or "Dilithium-3")
- `"ML-DSA-87"` (not "Dilithium5", "DILITHIUM_5", or "Dilithium-5")
