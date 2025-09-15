#!/usr/bin/env python3
"""
Environment checker for liboqs and cryptography availability.
Prints versions and lists enabled KEM and Signature mechanisms.
"""
try:
    import oqs.oqs as oqs
except ImportError as e:
    print("liboqs-python not available:", e)
    raise SystemExit(1)

from typing import Iterable


def _fmt_list(items: Iterable[str], max_items: int = 20) -> str:
    items = list(items)
    if len(items) <= max_items:
        return ", ".join(items)
    return ", ".join(items[:max_items]) + f" ... (+{len(items)-max_items} more)"


def main():
    try:
        ver = oqs.oqs_version()
    except Exception:
        ver = "unknown"
    try:
        pyver = oqs.oqs_python_version()
    except Exception:
        pyver = "unknown"

    print("liboqs:")
    print("  native version:", ver)
    print("  python wrapper:", pyver)

    kems = oqs.get_enabled_kem_mechanisms()
    sigs = oqs.get_enabled_sig_mechanisms()
    print(f"Enabled KEMs ({len(kems)}):", _fmt_list(kems))
    print(f"Enabled Signatures ({len(sigs)}):", _fmt_list(sigs))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
