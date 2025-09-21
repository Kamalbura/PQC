# liboqs Mapping: SPHINCS+ (SLH-DSA) Algorithms

## Repository Implementation → liboqs Reference Mapping

### SPHINCS+-SHA2-128f-simple
**Repository Files**: `drone_sphincs_sha2_128f.py`, `gcs_sphincs_sha2_128f.py`
**liboqs Algorithm Name**: `"SPHINCS+-SHA2-128f-simple"`
**Repository Usage**: `"SPHINCS+-SHA2-128f-simple"` ✓ CORRECT

#### Function Mappings:
- `spx.generate_keypair()` → `oqs.Signature.generate_keypair()`
- `spx.sign(message)` → `oqs.Signature.sign(message)`
- `spx.verify(message, signature, public_key)` → `oqs.Signature.verify(message, signature, public_key)`

#### Expected Parameters:
- Public Key Length: 32 bytes
- Secret Key Length: 64 bytes
- Signature Length: 7856 bytes

### SPHINCS+-SHA2-256f-simple
**Repository Files**: `drone_sphincs_sha2_256f.py`, `gcs_sphincs_sha2_256f.py`
**liboqs Algorithm Name**: `"SPHINCS+-SHA2-256f-simple"`
**Repository Usage**: Needs verification

### SPHINCS+-HARAKA-128f-simple
**Repository Files**: `drone_sphincs_haraka_128f.py`, `gcs_sphincs_haraka_128f.py`
**liboqs Algorithm Name**: `"SPHINCS+-HARAKA-128f-simple"`
**Repository Usage**: Needs verification

### SPHINCS+-HARAKA-256f-simple
**Repository Files**: `drone_sphincs_haraka_256f.py`, `gcs_sphincs_haraka_256f.py`
**liboqs Algorithm Name**: `"SPHINCS+-HARAKA-256f-simple"`
**Repository Usage**: Needs verification

## Critical Issues Found
1. **INCORRECT KEY EXCHANGE**: Uses deprecated `"Kyber768"` instead of `"ML-KEM-768"`
2. **LARGE SIGNATURES**: SPHINCS+ signatures are very large (7856+ bytes) - may cause network issues
3. **STATELESS BUT SLOW**: Hash-based signatures are quantum-secure but computationally expensive

## Security Parameters (NIST Levels)
- SPHINCS+-128f: NIST Security Level 1 (128-bit classical security)
- SPHINCS+-256f: NIST Security Level 5 (256-bit classical security)

## Implementation Notes
- SPHINCS+ is stateless (no key state management required)
- Very large signature sizes compared to other PQC algorithms
- Hash-based security provides strong quantum resistance
- Performance considerations for real-time UAV applications
