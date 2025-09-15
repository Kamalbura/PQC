# liboqs Mapping: Kyber (ML-KEM) Algorithms

## Repository Implementation → liboqs Reference Mapping

### ML-KEM-512 (Kyber-512)
**Repository Files**: `drone_kyber_512.py`, `gcs_kyber_512.py`
**liboqs Algorithm Name**: `"ML-KEM-512"`
**Repository Usage**: `"ML-KEM-512"` ✓ CORRECT

#### Function Mappings:
- `kem.generate_keypair()` → `oqs.KeyEncapsulation.generate_keypair()`
- `kem.encap_secret(public_key)` → `oqs.KeyEncapsulation.encap_secret(public_key)`
- `kem.decap_secret(ciphertext)` → `oqs.KeyEncapsulation.decap_secret(ciphertext)`

#### Expected Parameters:
- Public Key Length: 800 bytes
- Secret Key Length: 1632 bytes  
- Ciphertext Length: 768 bytes
- Shared Secret Length: 32 bytes

### ML-KEM-768 (Kyber-768)
**Repository Files**: `drone_kyber_768.py`, `gcs_kyber_768.py`
**liboqs Algorithm Name**: `"ML-KEM-768"`
**Repository Usage**: Mixed - some use `"Kyber768"` ❌ INCORRECT

#### Issues Found:
- `drone_falcon512.py:79` uses `"Kyber768"` instead of `"ML-KEM-768"`
- `drone_sphincs_sha2_128f.py:81` uses `"Kyber768"` instead of `"ML-KEM-768"`

### ML-KEM-1024 (Kyber-1024)
**Repository Files**: `drone_kyber_1024.py`, `gcs_kyber_1024.py`
**liboqs Algorithm Name**: `"ML-KEM-1024"`
**Repository Usage**: Needs verification

## Security Parameters (NIST Levels)
- ML-KEM-512: NIST Security Level 1 (128-bit classical, ~2^143 quantum)
- ML-KEM-768: NIST Security Level 3 (192-bit classical, ~2^207 quantum)  
- ML-KEM-1024: NIST Security Level 5 (256-bit classical, ~2^272 quantum)

## Canonical Algorithm Names
All implementations should use the standardized ML-KEM names:
- `"ML-KEM-512"` (not "Kyber512", "KYBER_512", or "Kyber-512")
- `"ML-KEM-768"` (not "Kyber768", "KYBER_768", or "Kyber-768")
- `"ML-KEM-1024"` (not "Kyber1024", "KYBER_1024", or "Kyber-1024")
