# Critical Security Patch: Disable Insecure ASCON Implementation

## Issue
The ASCON drone implementation uses an insecure 16-byte pre-shared key exchange over plain TCP without authentication or integrity protection.

## Risk Level
**CRITICAL** - Complete compromise of cryptographic security

## Patch Description
Disables the insecure implementation by raising `NotImplementedError` at startup to prevent accidental deployment.

## Testing
```bash
python drone/drone_ascon.py
# Should raise NotImplementedError with security warning
```

## Next Steps
1. Implement proper authenticated key exchange (Kyber + signatures)
2. Add mutual authentication between GCS and drone
3. Use TLS for key exchange transport
4. Implement proper KDF for symmetric key derivation
