# PQC Drone/GCS — Implementation (as-is)

Date: 2025-09-23
Scope: This document describes exactly how the current repository works, based on the code in this tree. No speculation or future plans — only what is implemented.

## Top-level architecture

There are two proxy styles implemented side-by-side:

- Classic per-algorithm, two-thread proxies
  - Location: `drone/*.py` and `gcs/*.py`
  - Each algorithm has a Drone-side and GCS-side script
  - Two UDP threads per process (see details below)

- Async single-port proxy (preferred for new work)
  - Core: `async_proxy.py` (asyncio) + `singleport_common.py` (handshakes + crypto)
  - Unified CLI/runner: `run_proxy.py`
  - Thin wrappers: `sdrone/*` and `sgcs/*` (call into the common runner)

All proxies exchange keys over TCP, then transport application traffic over UDP with AES-GCM framing.

## Configuration and ports

- Central configuration is preferred via `project_ip_config.py`.
  - If absent, classic proxies use `drone/ip_config.py` or `gcs/ip_config.py`.
  - The async wrappers under `sdrone/` and `sgcs/` use their own `ip_config` modules.

- Fixed port roles (as used throughout the codebase):
  - TCP key exchange (KEX): `5800` (`PORT_KEY_EXCHANGE`)
  - Commands path (GCS → Drone):
    - GCS app → GCS proxy plaintext commands listener: `5810`
    - GCS proxy → Drone proxy encrypted public socket: `5811`
    - Drone proxy → Drone app decrypted forward: `5812`
  - Telemetry path (Drone → GCS):
    - Drone app → Drone proxy plaintext telemetry listener: `5820`
    - Drone proxy → GCS proxy encrypted public socket: `5821`
    - GCS proxy → GCS app decrypted forward: `5822`

Notes:
- In `singleport_common.run_proxy()`, if `public_port` is not supplied, it defaults to `5821` for role `gcs` and `5811` for role `drone` (matching the public encrypted sockets).

## Crypto and framing (transport)

- Key exchange and signatures use liboqs when available.
  - KEM (Kyber / ML-KEM): `ML-KEM-512`, `ML-KEM-768`, `ML-KEM-1024`
  - Signatures: Dilithium2/3/5, Falcon-512/1024, SPHINCS+ (SHA2 and Haraka variants)
  - Mapping from short algo tags to liboqs names appears in `singleport_common.py`.

- Transport encryption: AES-256-GCM
  - Nonce/IV length: `NONCE_IV_SIZE = 12` bytes
  - Framing: classic scripts build nonce + ciphertext; the single-port path uses `MAGIC_BYTES + nonce + ciphertext` (see `singleport_common.py`).

- Handshake paths implemented in `singleport_common.py` (used by the async runner):
  - KEM: `tcp_key_exchange_gcs()` and `tcp_key_exchange_drone()`
  - Signatures: `tcp_signature_handshake_gcs()` and `tcp_signature_handshake_drone()`
  - Signature paths exchange signature public keys and also derive the AES key for transport.

## Classic proxies (two threads)

Each classic proxy script under `drone/` or `gcs/` follows the same pattern:

- Drone side
  - Thread A (telemetry → GCS):
    - UDP listen on `PORT_DRONE_LISTEN_PLAINTEXT_TLM` (5820)
    - Encrypt/sign as appropriate and send to GCS public encrypted port (5821)
  - Thread B (GCS commands → Drone):
    - UDP listen on `PORT_DRONE_LISTEN_ENCRYPTED_CMD` (5811)
    - Decrypt/verify and forward plaintext to `PORT_DRONE_FORWARD_DECRYPTED_CMD` (5812)

- GCS side
  - Thread A (Drone telemetry → GCS app):
    - UDP listen on `PORT_GCS_LISTEN_ENCRYPTED_TLM` (5821)
    - Decrypt/verify and forward plaintext to `PORT_GCS_FORWARD_DECRYPTED_TLM` (5822)
  - Thread B (GCS app commands → Drone):
    - UDP listen on `PORT_GCS_LISTEN_PLAINTEXT_CMD` (5810)
    - Encrypt/sign and send to Drone public encrypted port (5811)

- TCP key exchange
  - GCS side runs a TCP server on `PORT_KEY_EXCHANGE` (5800)
  - Drone side connects to this server to complete KEM/signature handshake and derive the AES-256 key

- Bind robustness (classic)
  - UDP (and where applicable TCP) listeners first try the configured host (from the relevant `ip_config`), and on `OSError` fall back to `0.0.0.0`. Logs indicate the fallback.

- Algorithm-specific files (samples)
  - Kyber (KEM): `drone/drone_kyber_768.py` ↔ `gcs/gcs_kyber_768.py` (also 512/1024 variants)
  - Dilithium (signature): `drone/drone_dilithium3.py` ↔ `gcs/gcs_dilithium3.py` (also 2/5 variants)
  - Falcon (signature): `drone/drone_falcon512.py` ↔ `gcs/gcs_falcon512.py` (also 1024)
  - SPHINCS+ (signature): SHA2 and Haraka variants under `drone/` and `gcs/`
  - Lightweight ciphers (research/demo): `ascon`, `speck`, `hight`, `camellia`, `printcipher`

## Async single-port proxy

- Entry points
  - `run_proxy.py`: CLI wrapper (modes: `proxy`, `benchmark` (Linux), placeholder `rl-inference`)
  - `async_proxy.py`: runs the async proxy; relies on `singleport_common.py` for handshakes and AES key derivation
  - Wrappers under `sdrone/` and `sgcs/` show how to invoke the runner for each role

- Sockets and tasks
  - Single public UDP socket bound to the role’s encrypted public port (`5821` for GCS, `5811` for Drone)
  - Two local UDP sockets (ports passed in):
    - local-in: plaintext from the local app (e.g., MAVProxy)
    - local-out: decrypted plaintext forwarded back to the local app
  - Two asyncio tasks:
    - public_recv_loop: decrypts from public socket and forwards plaintext to local-out
    - local_recv_loop: encrypts from local-in and sends to the remote public socket
  - Heavy crypto is offloaded to the default thread pool to avoid blocking (see `async_proxy.py`).

- Algorithm selection
  - `async_proxy.py` checks the `algo` tag and chooses signature handshakes (Dilithium/Falcon/SPHINCS) or KEM (Kyber 512/768/1024) accordingly.
  - Default public ports mirror the classic schema: 5821 (GCS) / 5811 (Drone) if not explicitly supplied.

## PRINTcipher specifics (research/demo)

- Files: `drone/drone_printcipher.py`, `gcs/gcs_printcipher.py`
- Key exchange over TCP (5800):
  - GCS generates an 80-bit PRINTcipher key and sends it to the drone.
  - Both derive a 256-bit AES-GCM key via PBKDF2 (see code).
- Transport uses AES-256-GCM (nonce length 12).
- Flows follow the same commands/telemetry roles and ports as other classic proxies.

## Error handling and fallbacks

- Bind fallbacks are implemented widely for UDP listeners and TCP key-exchange servers: try configured host, fall back to `0.0.0.0` on failure (with a log message).
- liboqs is preferred for KEM/signatures. Classic scripts expect liboqs; the async runner shares handshake logic in `singleport_common.py`, which contains the full handshake path and framing logic. (See `singleport_common.py` for exact behavior.)

## How to run (as implemented)

- Async (unified runner)
  - GCS role uses public encrypted telemetry port 5821; Drone uses 5811.
  - `run_proxy.py` selects role-specific public and local ports from the config files.

```powershell
# Example: GCS side (Kyber-768)
python run_proxy.py --role gcs --algo k768

# Example: Drone side (Kyber-768)
python run_proxy.py --role drone --algo k768 --gcs-host <GCS_HOST>
```

- Classic per-algorithm (reference/testing)

```powershell
# Example: Kyber-768 classic pair
python gcs/gcs_kyber_768.py
python drone/drone_kyber_768.py
```

## Key files (by responsibility)

- Async path: `async_proxy.py`, `run_proxy.py`, `singleport_common.py`
- Classic proxies: `drone/*.py`, `gcs/*.py`
- Config: `project_ip_config.py` (preferred), plus role-specific `*/ip_config.py`
- Wrappers: `sdrone/*`, `sgcs/*` (examples for single-port runner usage)
- Tests and legacy utilities: `legacy/*` (includes algorithm validation and smoke examples)

## Concurrency summary

- Classic proxies: two threads per process (one per direction).
- Async runner: two asyncio tasks (one per direction) on a single UDP public socket plus two local UDP sockets.

## Invariants (observed in code)

- Ports and roles are consistent with the schema above.
- AES-256-GCM uses 12-byte nonces across implementations.
- Message framing is consistent per path (classic vs single-port) — do not mix framers.
- Drone and GCS roles are symmetric opposites for commands/telemetry.

---
If you need file-level details for a specific algorithm, reference the corresponding `drone/drone_<algo>.py` and `gcs/gcs_<algo>.py` pair, or the single-port runner in `singleport_common.py` and `async_proxy.py`. This document will be updated only to reflect actual code changes.
