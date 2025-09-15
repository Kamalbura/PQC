#!/usr/bin/env python3
"""
Smoke test: Signature sign/verify across selected liboqs algorithms.
Skips gracefully if an algorithm is not enabled in the current liboqs build.
"""
import time

try:
    import oqs.oqs as oqs
except ImportError as e:
    print("[SKIP] liboqs-python not available:", e)
    raise SystemExit(0)

ALGOS = [
    "Dilithium2",
    "Dilithium3",
    "Dilithium5",
    "Falcon-512",
    "Falcon-1024",
    "SPHINCS+-SHA2-128f-simple",
    "SPHINCS+-SHA2-256f-simple",
    "SPHINCS+-Haraka-128f-simple",
    "SPHINCS+-Haraka-256f-simple",
]


def main():
    enabled = set(oqs.get_enabled_sig_mechanisms())
    msg = b"mavlink:test-message"
    passed = 0
    skipped = 0
    for alg in ALGOS:
        if alg not in enabled:
            print(f"[SKIP] {alg} not enabled")
            skipped += 1
            continue
        try:
            s = oqs.Signature(alg)
            t0 = time.perf_counter()
            pk = s.generate_keypair()
            t1 = time.perf_counter()
            sig = s.sign(msg)
            t2 = time.perf_counter()
            ok = s.verify(msg, sig, pk)
            t3 = time.perf_counter()
            if not ok:
                print(f"[FAIL] {alg} verify returned False")
                continue
            print(f"[PASS] {alg} | keypair={(t1-t0)*1000:.2f} ms sign={(t2-t1)*1000:.2f} ms verify={(t3-t2)*1000:.2f} ms")
            passed += 1
        except Exception as e:
            print(f"[FAIL] {alg}: {e}")
    print(f"Summary: pass={passed} skip={skipped} (enabled={len(enabled)})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
