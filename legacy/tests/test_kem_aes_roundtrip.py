#!/usr/bin/env python3
"""
Smoke test: KEM (Kyber-768) + AES-256-GCM roundtrip.
- Simulates GCS keypair generation
- Drone encapsulates
- Both derive AES key via SHA-256(shared_secret)
- Encrypt/decrypt a sample payload both directions
"""
import os
import time
import hashlib

try:
    import oqs.oqs as oqs
except ImportError as e:
    print("[SKIP] liboqs-python not available:", e)
    raise SystemExit(0)

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError as e:
    print("[SKIP] cryptography not available:", e)
    raise SystemExit(0)


def derive_key(shared_secret: bytes) -> bytes:
    return hashlib.sha256(shared_secret).digest()


def aes_encrypt(key: bytes, pt: bytes) -> bytes:
    n = os.urandom(12)
    ct = AESGCM(key).encrypt(n, pt, None)
    return n + ct


def aes_decrypt(key: bytes, em: bytes) -> bytes:
    n, ct = em[:12], em[12:]
    return AESGCM(key).decrypt(n, ct, None)


def main():
    alg = "ML-KEM-768"
    if alg not in oqs.get_enabled_kem_mechanisms():
        print(f"[SKIP] {alg} not enabled in this liboqs build")
        return 0

    kem = oqs.KeyEncapsulation(alg)
    t0 = time.perf_counter()
    pk = kem.generate_keypair()
    t1 = time.perf_counter()
    ct, ss_d = kem.encap_secret(pk)
    t2 = time.perf_counter()
    ss_g = kem.decap_secret(ct)
    t3 = time.perf_counter()

    k_d = derive_key(ss_d)
    k_g = derive_key(ss_g)
    assert k_d == k_g, "Derived AES keys mismatch"

    pkt = b"mavlink:heartbeat"
    enc = aes_encrypt(k_d, pkt)
    dec = aes_decrypt(k_g, enc)
    assert dec == pkt, "AES roundtrip mismatch"

    # reverse direction
    enc2 = aes_encrypt(k_g, pkt)
    dec2 = aes_decrypt(k_d, enc2)
    assert dec2 == pkt, "AES reverse roundtrip mismatch"

    print("[PASS] KEM+AES roundtrip")
    print(f"  keypair: {(t1-t0)*1000:.2f} ms | encap: {(t2-t1)*1000:.2f} ms | decap: {(t3-t2)*1000:.2f} ms")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
