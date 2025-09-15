# Post-Quantum Cryptography Implementation Documentation
## NIST Security Level Framework for Drone-GCS Communication

### Executive Summary

This document provides comprehensive documentation for our Post-Quantum Cryptographic (PQC) implementation targeting secure drone-to-Ground Control Station (GCS) communication. The framework is organized by NIST security levels and optimized for resource-constrained environments like Raspberry Pi 4B.

---

## Table of Contents

1. [NIST Security Level Overview](#nist-security-level-overview)
2. [Level 1 Algorithms (128-bit Security)](#level-1-algorithms-128-bit-security)
3. [Level 3 Algorithms (192-bit Security)](#level-3-algorithms-192-bit-security)
4. [Level 5 Algorithms (256-bit Security)](#level-5-algorithms-256-bit-security)
5. [Implementation Architecture](#implementation-architecture)
6. [Performance Analysis](#performance-analysis)
7. [Security Analysis](#security-analysis)
8. [Raspberry Pi Optimization](#raspberry-pi-optimization)
9. [References](#references)

---

## NIST Security Level Overview

The National Institute of Standards and Technology (NIST) defines security levels for post-quantum cryptographic algorithms based on their computational security strength compared to symmetric encryption standards:

| Security Level | Classical Equivalent | Quantum Attack Resistance | Use Case |
|----------------|---------------------|---------------------------|----------|
| **Level 1** | AES-128 (128-bit) | ~2^64 quantum operations | IoT, Real-time systems |
| **Level 3** | AES-192 (192-bit) | ~2^96 quantum operations | General applications |
| **Level 5** | AES-256 (256-bit) | ~2^128 quantum operations | High-security applications |

### Security Level Selection Criteria

- **Level 1**: Maximum performance, acceptable security for most IoT applications
- **Level 3**: Balanced security-performance tradeoff, recommended for most use cases
- **Level 5**: Maximum security for critical infrastructure and long-term protection

---

## Level 1 Algorithms (128-bit Security)

### Overview
Level 1 provides equivalent security to AES-128, offering the fastest performance with basic quantum resistance. Ideal for resource-constrained environments requiring real-time operation.

### 1. ML-KEM-512 (Module Lattice-Based Key Encapsulation Mechanism)

**Official Source**: [FIPS 203 - Module-Lattice-Based Key-Encapsulation Mechanism Standard](https://csrc.nist.gov/pubs/fips/203/final)

**Theory**: 
- Based on the Module Learning With Errors (M-LWE) problem
- Security relies on the hardness of finding short vectors in lattices
- Uses polynomial rings for efficiency

**Implementation Strategy**:
```python
# Key Generation
public_key, secret_key = kem.keypair()

# Encapsulation (GCS side)
ciphertext, shared_secret_gcs = kem.encap(public_key)

# Decapsulation (Drone side) 
shared_secret_drone = kem.decap(ciphertext)

# Derive AES-256 key
aes_key = HKDF(shared_secret, salt=b"drone-gcs-2024")
```

**Key Sizes**:
- Public Key: 800 bytes
- Secret Key: 1,632 bytes
- Ciphertext: 768 bytes
- Shared Secret: 32 bytes

**Security Basis**: M-LWE problem with security parameter n=512

### 2. ML-DSA-44 (Module Lattice-Based Digital Signature Algorithm)

**Official Source**: [FIPS 204 - Module-Lattice-Based Digital Signature Standard](https://csrc.nist.gov/pubs/fips/204/final)

**Theory**:
- Based on the CRYSTALS-Dilithium scheme
- Uses Module-SIS (Short Integer Solution) problem
- Implements Fiat-Shamir transformation for non-interactive proofs

**Implementation Strategy**:
```python
# Key Generation
public_key, secret_key = dsig.keypair()

# Signing
signature = dsig.sign(message, secret_key)

# Verification
is_valid = dsig.verify(message, signature, public_key)
```

**Key Sizes**:
- Public Key: 1,312 bytes
- Secret Key: 2,560 bytes
- Signature: 2,420 bytes

### 3. Falcon-512 (Fast Fourier Lattice-based Compact Signatures)

**Official Source**: [NIST PQC Round 3 Submission](https://falcon-sign.info/)

**Theory**:
- Based on NTRU lattices
- Uses Gaussian sampling for signature generation
- Optimized for compact signatures

**Implementation Strategy**:
```python
# Optimized for memory-constrained devices
# Smallest signature size in Level 1
# Trade-off: Higher computation for smaller signatures
```

**Key Sizes**:
- Public Key: 897 bytes
- Secret Key: 1,281 bytes
- Signature: 690 bytes (smallest!)

### 4. SPHINCS+-SHA2-128f (Hash-Based Signatures)

**Official Source**: [FIPS 205 - Stateless Hash-Based Digital Signature Standard](https://csrc.nist.gov/pubs/fips/205/final)

**Theory**:
- Based on hash function security (SHA-256)
- Stateless (no signature counter required)
- Few-Time Signature (FTS) construction

**Implementation Strategy**:
```python
# Hash-based security - only relies on SHA-256
# No lattice problems or number theory
# Conservative security assumption
```

**Key Sizes**:
- Public Key: 32 bytes (smallest!)
- Secret Key: 64 bytes
- Signature: 17,088 bytes (largest!)

### 5. SPHINCS+-Haraka-128f

**Status**: ⚠️ Implementation Issues (Under Investigation)

**Theory**: Similar to SHA2 variant but uses Haraka hash function for better performance on AES-enabled processors.

---

## Level 3 Algorithms (192-bit Security)

### Overview
Level 3 provides equivalent security to AES-192, offering strong security with reasonable performance. Recommended for most practical applications requiring long-term security.

### 1. ML-KEM-768

**Enhanced Security**: Uses larger parameters (n=768) for increased M-LWE hardness

**Key Sizes**:
- Public Key: 1,184 bytes
- Secret Key: 2,400 bytes
- Ciphertext: 1,088 bytes

### 2. ML-DSA-65

**Enhanced Security**: Increased parameters for stronger Module-SIS security

**Key Sizes**:
- Public Key: 1,952 bytes
- Secret Key: 4,000 bytes
- Signature: 3,293 bytes

---

## Level 5 Algorithms (256-bit Security)

### Overview
Level 5 provides equivalent security to AES-256, offering maximum security for critical applications. Highest computational cost but strongest quantum resistance.

### 1. ML-KEM-1024

**Maximum Security**: Largest parameter set (n=1024) for strongest M-LWE security

**Key Sizes**:
- Public Key: 1,568 bytes
- Secret Key: 3,168 bytes
- Ciphertext: 1,568 bytes

### 2. ML-DSA-87

**Maximum Security**: Highest parameter set for strongest Module-SIS security

**Key Sizes**:
- Public Key: 2,592 bytes
- Secret Key: 4,864 bytes
- Signature: 4,595 bytes

### 3. Falcon-1024

**Key Sizes**:
- Public Key: 1,793 bytes
- Secret Key: 2,305 bytes
- Signature: 1,330 bytes

### 4. SPHINCS+-SHA2-256f & SPHINCS+-Haraka-256f

**Maximum Hash-Based Security**: 256-bit security level for long-term protection

---

## Implementation Architecture

### Proxy-Based Design

```
Application Layer:    [Drone App] ←→ [GCS App]
                         ↕              ↕
Crypto Proxy Layer:   [PQC Proxy] ←→ [PQC Proxy]
                         ↕              ↕
Network Layer:        [Encrypted UDP/TCP Packets]
```

### Key Exchange Protocol

1. **TCP Handshake** (Port 5800): Establish PQC key exchange
2. **Key Encapsulation**: GCS generates keypair, drone encapsulates
3. **Shared Secret**: Both derive AES-256-GCM key
4. **UDP Streams**: Secure command/telemetry on ports 5810-5822

### Message Flow

```
Plaintext → AES-256-GCM Encrypt → Network → AES-256-GCM Decrypt → Plaintext
```

---

## Performance Analysis

### Computational Complexity

| Algorithm | Key Gen | Encrypt/Sign | Decrypt/Verify |
|-----------|---------|--------------|----------------|
| ML-KEM-512 | O(n²) | O(n log n) | O(n log n) |
| ML-DSA-44 | O(n²) | O(n²) | O(n²) |
| Falcon-512 | O(n log n) | O(n log n) | O(n log n) |

### Expected Performance Hierarchy
1. **Fastest**: ML-KEM algorithms (efficient polynomial operations)
2. **Moderate**: Falcon algorithms (FFT optimization)
3. **Slowest**: SPHINCS+ algorithms (multiple hash operations)

---

## Security Analysis

### Quantum Attack Models

**Grover's Algorithm**: Provides quadratic speedup for searching
- Level 1: Resistant to ~2^64 Grover attacks
- Level 3: Resistant to ~2^96 Grover attacks  
- Level 5: Resistant to ~2^128 Grover attacks

**Shor's Algorithm**: Efficiently breaks RSA/ECC, ineffective against lattice problems

### Security Assumptions

1. **Lattice-Based (ML-KEM, ML-DSA, Falcon)**: 
   - Learning With Errors (LWE) hardness
   - Short Vector Problem (SVP) hardness
   
2. **Hash-Based (SPHINCS+)**:
   - Cryptographic hash function security
   - Most conservative assumption

---

## Raspberry Pi Optimization

### Hardware Specifications (Pi 4B)
- **CPU**: Quad-core ARM Cortex-A72 @ 1.5GHz
- **Memory**: 4GB/8GB LPDDR4
- **Architecture**: ARMv8 64-bit

### Optimization Strategies

1. **Algorithm Selection**: Prefer Level 1 for real-time applications
2. **Memory Management**: Minimize key storage overhead
3. **CPU Scheduling**: Use nice values for priority management
4. **Network Optimization**: UDP for low latency, TCP for key exchange

### Power Consumption Considerations

- **Computation**: ~2-4W during crypto operations
- **Network I/O**: ~0.5-1W baseline
- **Algorithm Impact**: Level 5 algorithms consume 2-3x more power

---

## References

1. [NIST Post-Quantum Cryptography Standardization](https://csrc.nist.gov/projects/post-quantum-cryptography)
2. [FIPS 203: ML-KEM Standard](https://csrc.nist.gov/pubs/fips/203/final)
3. [FIPS 204: ML-DSA Standard](https://csrc.nist.gov/pubs/fips/204/final)
4. [FIPS 205: SPHINCS+ Standard](https://csrc.nist.gov/pubs/fips/205/final)
5. [Falcon Specification](https://falcon-sign.info/)
6. [liboqs Documentation](https://github.com/open-quantum-safe/liboqs)
7. [CRYSTALS-Kyber](https://pq-crystals.org/kyber/)
8. [CRYSTALS-Dilithium](https://pq-crystals.org/dilithium/)

---

*This documentation is part of the Post-Quantum Secure Drone Communication Research Project, focusing on practical implementation of NIST-standardized PQC algorithms for resource-constrained UAV systems.*