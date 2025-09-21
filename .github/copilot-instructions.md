# Post-Quantum Secure Drone Communication System - AI Coding Agent Instructions

## Project Overview
This is a **research-grade Post-Quantum Cryptographic (PQC) secure communication framework** between drones and Ground Control Stations (GCS). The system implements a proxy-based architecture comparing pre-quantum and post-quantum algorithms for UAV communications.

## Critical Architecture Pattern: Proxy-Based Design

### Core Concept
Each cryptographic algorithm runs as a **dedicated proxy pair** (`drone_[algo].py` / `gcs_[algo].py`) that intercepts, processes, and forwards MAVLink traffic. Proxies sit between applications and the network, handling all crypto operations transparently.

### Mandatory Project Structure
```
drone/
├── ip_config.py          # Network configuration (drone-side)
├── drone_ascon.py        # ASCON-128 AEAD proxy
├── drone_kyber_768.py    # ML-KEM-768 key exchange proxy  
├── drone_dilithium.py    # ML-DSA signature proxy
└── ... (per-algorithm proxies)
gcs/
├── ip_config.py          # Network configuration (GCS-side)
├── gcs_ascon.py         # ASCON-128 AEAD proxy
├── gcs_kyber_768.py     # ML-KEM-768 key exchange proxy
├── gcs_dilithium.py     # ML-DSA signature proxy
└── ... (per-algorithm proxies)
```

## Network Architecture (Fixed Port Schema)

**All communication uses standardized ports (5800-5822):**

- **5800**: TCP Key Exchange (Kyber/Dilithium/Falcon/SPHINCS+ setup)
- **5810-5812**: UDP Command Flow (GCS→Drone: plaintext→encrypted→decrypted)
- **5820-5822**: UDP Telemetry Flow (Drone→GCS: plaintext→encrypted→decrypted)

### ip_config.py Pattern
Always use centralized network configuration:
```python
GCS_HOST = "192.168.0.104"
DRONE_HOST = "192.168.0.101" 
PORT_KEY_EXCHANGE = 5800
PORT_GCS_LISTEN_PLAINTEXT_CMD = 5810
# ... (complete port definitions in both drone/ and gcs/ versions)
```

## Algorithm Implementation Requirements

### Pre-Quantum Algorithms (128-bit keys for fair comparison)
- **ASCON-128**: NIST Lightweight AEAD winner
- **Camellia-128**: ISO/IEC standard block cipher  
- **HIGHT**: Korean lightweight cipher
- **PRINTcipher**: Ultra-lightweight research cipher

### Post-Quantum Algorithms (NIST security levels 1,3,5)
- **ML-KEM (Kyber)**: Key encapsulation (512/768/1024)
- **ML-DSA (Dilithium)**: Digital signatures (2/3/5)
- **Falcon**: Compact lattice signatures (512/1024)
- **SPHINCS+**: Hash-based signatures (multiple variants)

## Critical Implementation Rules

### 1. liboqs Dependency
**ALWAYS use liboqs for PQC algorithms:**
```python
try:
    import oqs.oqs as oqs
    USING_LIBOQS = True
    kem = oqs.KeyEncapsulation("ML-KEM-768")
except ImportError:
    # Only basic fallback for testing - clearly mark as insecure
    print("[WARNING] liboqs not found, using insecure fallback")
```

### 2. Proxy Threading Pattern
Each proxy must implement **exactly two daemon threads**:
```python
def telemetry_to_gcs_thread():  # Encrypt outgoing
def commands_from_gcs_thread(): # Decrypt incoming

t1 = threading.Thread(target=telemetry_to_gcs_thread, daemon=True)
# Copilot / AI agent quick instructions — PQC Drone/GCS repo

This repository is a proxy-based research framework that compares pre-quantum and post-quantum crypto for UAV comms. Keep instructions short and action-oriented: preserve protocol ports, the proxy threading pattern, and liboqs usage.

Key facts (read before editing):
- Two sides: `drone/` and `gcs/`. Each algorithm has a proxy pair: `drone_<algo>.py` and `gcs_<algo>.py` (example: `drone/drone_kyber_512.py` ↔ `gcs/gcs_kyber_512.py`).
- Central network config: `drone/ip_config.py` and `gcs/ip_config.py` hold hosts and fixed ports. PORT_KEY_EXCHANGE = 5800 (TCP). UDP command ports 5810–5812, telemetry 5820–5822.
- Every proxy implements exactly two daemon threads: one encrypting telemetry out, one decrypting commands in. See `drone_*` files for the concrete pattern.

Important implementation rules to preserve:
- Prefer liboqs for PQC: code uses `import oqs.oqs as oqs` and falls back only for local testing — keep the import/try-except pattern and log clearly when liboqs is absent.
- Key exchange over TCP on port 5800: GCS sends pubkey, drone encapsulates and returns ciphertext; both derive `AES_KEY` (256-bit) for AES-GCM streams.
- Nonce size: `NONCE_IV_SIZE = 12`; encryption format = nonce || ciphertext (AES-GCM). Follow existing `encrypt_message` / `decrypt_message` layout.

Files & locations to check for examples and tests:
- Reference implementations: `drone/drone_kyber_512.py`, `gcs/gcs_kyber_512.py` (use these as templates).
- Network config: `drone/ip_config.py`, `gcs/ip_config.py`.
- Tests and validation scripts: `legacy/test_mlkem_validation.py`, `legacy/test_mldsa_validation.py`, `legacy/test_sphincs_validation.py`, and `legacy/test_pqc_with_dummy_apps.py`.
- Project-level notes and reports: `legacy/README.md`, `legacy/PQC_Drone_Implementation.ipynb`, `legacy/SECURITY_AUDIT_REPORT.md`.

Quick-start for local dev (assumes Python env with dependencies):
- Install dependencies: check `legacy/requirements.txt` and install into a venv.
- Run GCS key-exchange reference in one terminal: `python gcs/gcs_kyber_512.py`.
- Run Drone reference in another terminal: `python drone/drone_kyber_512.py`.
(These scripts are the canonical fast-path to verify the TCP key exchange + AES-GCM stream.)

What AI agents should do (concrete):
- When adding or modifying an algorithm proxy: keep the two-thread structure and centralize host/port usage via `ip_config.py`.
- When touching PQC code, prefer `oqs` use. If adding a fallback, add an explicit runtime-warning and tag the code path as insecure.
- Preserve message framing (nonce + ct) and `NONCE_IV_SIZE = 12` across changes to keep compatibility.

When proposing tests or changes, reference specific files and include a one-line smoke test example (e.g., "run `gcs/gcs_kyber_512.py` and `drone/drone_kyber_512.py` together and verify key derivation logs").

If anything here is ambiguous, point to the nearest example implementation (`drone_kyber_512.py` / `gcs_kyber_512.py`) and ask for which algorithm/parameter set to modify next.

— End of agent instructions (concise, actionable)