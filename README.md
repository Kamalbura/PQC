# Post-Quantum Secure Drone Communication System

This project provides a research-grade proxy-based framework to secure MAVLink traffic between Ground Control Station (GCS) and UAV (Drone) with pre-quantum and post-quantum cryptography.

- PQC: Kyber (ML-KEM) key exchange, Dilithium/Falcon/SPHINCS+ signatures
- Transport: AES-256-GCM (key derived from KEM shared secret)
- Architecture: Proxies with two daemon threads per side and fixed ports

## Prerequisites

- Python 3.10+
- Windows, Linux, or macOS
- Recommended: Virtualenv/conda

Install dependencies:

```powershell
python -m pip install -r requirements.txt
```

Optional: Run environment check to see which algorithms are enabled in your liboqs build:

```powershell
python tools/check_env.py
```

## Run a proxy pair (example: SPHINCS+-SHA2-128f)

Start GCS (terminal 1):

```powershell
python gcs/gcs_sphincs_sha2_128f.py
```

Start Drone (terminal 2):

```powershell
python drone/drone_sphincs_sha2_128f.py
```

Send plaintext commands to `PORT_GCS_LISTEN_PLAINTEXT_CMD` and plaintext telemetry to `PORT_DRONE_LISTEN_PLAINTEXT_TLM`. Encrypted flows will appear on the encrypted ports; decrypted results are forwarded to the designated forward ports. All constants live in `gcs/ip_config.py` and `drone/ip_config.py`.

## Smoke tests

KEM + AES roundtrip:

```powershell
python tests/test_kem_aes_roundtrip.py
```

Signature suite (skips algorithms not enabled in your liboqs build):

```powershell
python tests/test_sign_verify_suite.py
```

## Notes

- If an algorithm is reported as "not enabled", rebuild liboqs with that mechanism enabled or use a prebuilt liboqs supporting it.
- Firewall: Ensure UDP/TCP ports 5800–5822 are allowed between GCS host and Drone host IPs.
- For pre-quantum ciphers (ASCON, Camellia, HIGHT, PRINTcipher), ensure any extra packages are installed if you plan to run those proxies.

## License

Research/educational use; ensure compliance with local regulations for UAV control systems.
