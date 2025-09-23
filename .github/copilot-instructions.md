# PQC Drone/GCS — Copilot Guide (concise)

This repo is a proxy-based research framework to secure MAVLink traffic between Ground Control Station (GCS) and UAV using pre-quantum and post-quantum crypto.

## Architecture at a glance
- Two sides: `drone/` and `gcs/`. Classic per-algorithm proxies come in pairs: `drone_<algo>.py` ↔ `gcs_<algo>.py` (see `drone/drone_kyber_768.py`, `gcs/gcs_kyber_768.py`).
- Unified single-port runner: `run_proxy.py` wraps `async_proxy.py` (asyncio) and crypto in `singleport_common.py`.
- Central config preferred: `project_ip_config.py` (fallback to `drone/ip_config.py` and `gcs/ip_config.py`).

## Fixed ports (do not change)
- TCP key exchange: 5800
- Commands (GCS→Drone): 5810 plaintext → 5811 encrypted (public) → 5812 decrypted forward
- Telemetry (Drone→GCS): 5820 plaintext → 5821 encrypted (public) → 5822 decrypted forward

## Crypto rules you must preserve
- Use liboqs for PQC; keep this import pattern with explicit insecure fallback:
    `try: import oqs.oqs as oqs; USING_LIBOQS=True except ImportError: print('[WARNING] liboqs not found, using insecure fallback')`
- KEM mapping: `k512|k768|k1024` → `ML-KEM-512|768|1024`. Signatures: Dilithium2/3/5, Falcon-512/1024, SPHINCS+ variants.
- Handshakes on TCP: `tcp_key_exchange_*` (KEM) and `tcp_signature_handshake_*` (sign+seed). On signature failure, fallback to KEM.
- Transport: AES-256-GCM with `NONCE_IV_SIZE = 12`. Framing is strict: `MAGIC_BYTES + nonce + ciphertext`. Use `encrypt_message`/`decrypt_message` in `singleport_common.py`.

## Proxy concurrency patterns
- Classic proxies: exactly two daemon threads (encrypt telemetry out, decrypt commands in).
- Async single-port: two asyncio tasks (`public_recv_loop` decrypt→local, `local_recv_loop` encrypt→remote). Avoid blocking; offload heavy crypto to executor as in `async_proxy.py`.

## Run workflows (Windows PowerShell examples)
- Install deps: `python -m pip install -r legacy/requirements.txt`
- Unified runner:
    - GCS: `python run_proxy.py --role gcs --algo k768`
    - Drone: `python run_proxy.py --role drone --algo k768 --gcs-host <GCS_HOST>`
- Legacy pair (for reference/templates): `python gcs/gcs_kyber_768.py` and `python drone/drone_kyber_768.py`.
- Optional (Linux) benchmark: `python run_proxy.py --mode benchmark --duration 30`

## Conventions and gotchas
- Keep ports and framing unchanged; other components assume compatibility.
- Centralize host/ports via `project_ip_config.py`; do not hardcode.
- When adding an algorithm, mirror the pair pattern or plug into the async runner; preserve two-thread/two-task structure and port roles.
- Log clearly when insecure fallbacks are used.

## Pointers and tests
- Key files: `async_proxy.py`, `run_proxy.py`, `singleport_common.py`, `project_ip_config.py`, `drone/*.py`, `gcs/*.py`.
- Validation: `legacy/test_mlkem_validation.py`, `legacy/test_mldsa_validation.py`, `legacy/test_sphincs_validation.py`. Smoke test by running the Kyber pair and watching AES key derivation and encrypted UDP flow logs.

If any area is unclear (e.g., adding a new SPHINCS+ variant or port wiring), tell me what you’re changing and which side(s); I’ll extend this guide with a concrete example.
