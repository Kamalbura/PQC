#!/usr/bin/env python3
"""
Minimal single-port proxy common code used by sdrone/ and sgcs/ wrappers.

Design goals:
- Single external UDP socket per proxy (public_sock) and one local plain socket (local_sock).
- TCP key-exchange on port 5800. Try to use liboqs if available, otherwise fall back to an insecure random-derived key (clearly logged).
- AES-GCM with NONCE_IV_SIZE=12 framing: nonce || ciphertext.
- Small, robust code with clear logging and configurable timeouts.
"""
import socket
import threading
import time
import os
import argparse
import hashlib
import sys
from typing import Optional

try:
    import oqs.oqs as oqs  # preferred
    USING_LIBOQS = True
except Exception:
    try:
        import oqs  # alternate import styles
        USING_LIBOQS = True
    except Exception:
        oqs = None
        USING_LIBOQS = False

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except Exception:
    print("[singleport_common] Missing 'cryptography' package. Install via pip if you want AES-GCM.")
    AESGCM = None

# Defaults (match repository conventions)
PORT_KEY_EXCHANGE = 5800
NONCE_IV_SIZE = 12
AES_KEY_LEN = 32
SESSION_TIMEOUT = 120
BUFFER_SIZE = 65535

# Packet-level protocol protection: simple magic header to reject garbage before attempting crypto
MAGIC_BYTES = b'\xDE\xAD\xBE\xEF'


def log(prefix: str, *args):
    print(f"[{prefix}]", *args)


def derive_aes_key_fallback(random1: bytes, random2: bytes) -> bytes:
    # Deterministic key derivation for fallback: SHA-256(random1 || random2)
    return hashlib.sha256(random1 + random2).digest()


def tcp_key_exchange_gcs(host: str, kem_name: str, listen_port: int = PORT_KEY_EXCHANGE) -> bytes:
    # GCS acts as TCP server: accepts connection, sends its "public" material (if oqs available),
    # receives encaps (or random), and derives AES key. If liboqs is unavailable, exchange randoms.
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, listen_port))
    srv.listen(1)
    log('GCS-KEX', f'waiting for connection on {host}:{listen_port} (kem={kem_name})')
    conn, addr = srv.accept()
    with conn:
        log('GCS-KEX', 'connected by', addr)
        if USING_LIBOQS and oqs is not None:
            try:
                kem = oqs.KeyEncapsulation(kem_name)
                # try to generate keypair; API differences are handled defensively
                pub = None
                try:
                    pub = kem.generate_keypair()
                except Exception:
                    try:
                        # some bindings expose generate_keypair as generate_keypair()
                        pub = kem.generate_keypair()
                    except Exception:
                        pub = None
                if pub is None:
                    log('GCS-KEX', 'liboqs present but could not generate keypair; falling back')
                    raise RuntimeError('kem.generate_keypair() failed')
                # send public key
                conn.sendall(len(pub).to_bytes(4, 'big') + pub)
                # receive ciphertext
                clen = int.from_bytes(conn.recv(4), 'big')
                ct = conn.recv(clen)
                # decapsulate using helper that handles binding API differences
                try:
                    shared = _kem_decapsulate(kem, ct)
                except Exception as e:
                    log('GCS-KEX', 'decapsulation via liboqs failed:', e)
                    raise
                log('GCS-KEX', 'derived shared secret via liboqs')
                return hashlib.sha256(shared).digest()[:AES_KEY_LEN]
            except Exception as e:
                log('GCS-KEX', 'liboqs key-exchange failed:', e)

        # Fallback: exchange random seeds
        r = os.urandom(AES_KEY_LEN)
        conn.sendall(len(r).to_bytes(4, 'big') + r)
        clen = int.from_bytes(conn.recv(4), 'big')
        other = conn.recv(clen)
        key = derive_aes_key_fallback(r, other)
        log('GCS-KEX', 'derived AES key using fallback')
        return key


def tcp_key_exchange_drone(gcs_host: str, kem_name: str, connect_port: int = PORT_KEY_EXCHANGE) -> bytes:
    # Drone connects to GCS, receives public/material, encapsulates or sends random and derives shared key
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((gcs_host, connect_port))
    with s:
        if USING_LIBOQS and oqs is not None:
            try:
                kem = oqs.KeyEncapsulation(kem_name)
                # receive public key
                plen = int.from_bytes(s.recv(4), 'big')
                pub = s.recv(plen)
                # encapsulate using helper to handle API differences
                try:
                    ct, shared = _kem_encapsulate(kem, pub)
                except Exception as e:
                    log('DRONE-KEX', 'encapsulation via liboqs failed:', e)
                    raise
                s.sendall(len(ct).to_bytes(4, 'big') + ct)
                log('DRONE-KEX', 'encapsulated and derived shared secret via liboqs')
                return hashlib.sha256(shared).digest()[:AES_KEY_LEN]
            except Exception as e:
                log('DRONE-KEX', 'liboqs encapsulation failed:', e)

        # Fallback: receive random r from GCS, send our random, derive AES key
        plen = int.from_bytes(s.recv(4), 'big')
        r = s.recv(plen)
        other = os.urandom(AES_KEY_LEN)
        s.sendall(len(other).to_bytes(4, 'big') + other)
        key = derive_aes_key_fallback(r, other)
        log('DRONE-KEX', 'derived AES key using fallback')
        return key


def _kem_encapsulate(kem, pub: bytes):
    # Try common encapsulate API names and return (ct, shared)
    for name in ('encap_secret', 'encaps_cb', 'encapsulate', 'encap', 'encaps'):
        func = getattr(kem, name, None)
        if func is None:
            continue
        try:
            return func(pub)
        except Exception:
            continue
    raise AttributeError('No known encapsulate method found on KeyEncapsulation')


def _kem_decapsulate(kem, ct: bytes) -> bytes:
    for name in ('decap_secret', 'decaps_cb', 'decapsulate', 'decap', 'decaps'):
        func = getattr(kem, name, None)
        if func is None:
            continue
        try:
            return func(ct)
        except Exception:
            continue
    raise AttributeError('No known decapsulate method found on KeyEncapsulation')


def tcp_signature_handshake_gcs(host: str, sig_name: str, listen_port: int = PORT_KEY_EXCHANGE) -> Optional[bytes]:
    """GCS side: acts as TCP server for signature-authenticated seed exchange.

    Protocol:
    - Accept TCP connection
    - Generate signature keypair (pub_gcs, priv_gcs) if liboqs available
    - Send pub_gcs (len+bytes)
    - Receive pub_drone (len+bytes)
    - Generate seed_gcs, sign it, send len(seed)+seed + len(sig)+sig
    - Receive drone's seed+sig, verify
    - Derive AES key = SHA256(seed_gcs || seed_drone)
    - If liboqs not available, fallback to random seed exchange (insecure)
    """
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, listen_port))
    srv.listen(1)
    log('GCS-SIG', f'waiting for signature handshake on {host}:{listen_port} (sig={sig_name})')
    conn, addr = srv.accept()
    with conn:
        log('GCS-SIG', 'connected by', addr)
        if USING_LIBOQS and oqs is not None:
            try:
                sig = oqs.Signature(sig_name)
                # generate keypair
                try:
                    pub = sig.generate_keypair()
                except Exception:
                    try:
                        pub = sig.generate_keypair()
                    except Exception:
                        pub = None
                if pub is None:
                    raise RuntimeError('signature.generate_keypair failed')
                # send pub
                conn.sendall(len(pub).to_bytes(4, 'big') + pub)
                # receive pub_drone
                plen = int.from_bytes(conn.recv(4), 'big')
                pub_drone = conn.recv(plen)

                # generate seed and signature
                seed_gcs = os.urandom(AES_KEY_LEN)
                try:
                    sig_gcs = sig.sign(seed_gcs)
                except Exception:
                    sig_gcs = sig.sign_message(seed_gcs)
                # send seed and signature
                conn.sendall(len(seed_gcs).to_bytes(4, 'big') + seed_gcs + len(sig_gcs).to_bytes(4, 'big') + sig_gcs)

                # receive drone seed+sig
                slen = int.from_bytes(conn.recv(4), 'big')
                seed_drone = conn.recv(slen)
                siglen = int.from_bytes(conn.recv(4), 'big')
                sig_drone = conn.recv(siglen)

                # verify drone signature using pub_drone
                try:
                    ver = oqs.Signature(sig_name)
                    ok = ver.verify(seed_drone, sig_drone, pub_drone)
                except Exception:
                    try:
                        ver = oqs.Signature(sig_name)
                        ok = ver.verify_message(seed_drone, sig_drone, pub_drone)
                    except Exception:
                        ok = False

                if not ok:
                    log('GCS-SIG', 'signature verification failed; aborting handshake')
                    return None
                log('GCS-SIG', 'signature handshake succeeded')
                return hashlib.sha256(seed_gcs + seed_drone).digest()[:AES_KEY_LEN]
            except Exception as e:
                log('GCS-SIG', 'liboqs signature handshake failed:', e)

        # Fallback: exchange random seeds without signature
        r = os.urandom(AES_KEY_LEN)
        conn.sendall(len(r).to_bytes(4, 'big') + r)
        slen = int.from_bytes(conn.recv(4), 'big')
        other = conn.recv(slen)
        key = derive_aes_key_fallback(r, other)
        log('GCS-SIG', 'derived AES key using insecure fallback')
        return key


def tcp_signature_handshake_drone(gcs_host: str, sig_name: str, connect_port: int = PORT_KEY_EXCHANGE) -> Optional[bytes]:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((gcs_host, connect_port))
    with s:
        if USING_LIBOQS and oqs is not None:
            try:
                sig = oqs.Signature(sig_name)
                # receive pub_gcs
                plen = int.from_bytes(s.recv(4), 'big')
                pub_gcs = s.recv(plen)
                # generate own keypair
                try:
                    pub_drone = sig.generate_keypair()
                except Exception:
                    pub_drone = sig.generate_keypair()
                s.sendall(len(pub_drone).to_bytes(4, 'big') + pub_drone)

                # receive seed_gcs+sig
                slen = int.from_bytes(s.recv(4), 'big')
                seed_gcs = s.recv(slen)
                siglen = int.from_bytes(s.recv(4), 'big')
                sig_gcs = s.recv(siglen)

                # verify seed_gcs
                try:
                    ver = oqs.Signature(sig_name)
                    ok = ver.verify(seed_gcs, sig_gcs, pub_gcs)
                except Exception:
                    try:
                        ver = oqs.Signature(sig_name)
                        ok = ver.verify_message(seed_gcs, sig_gcs, pub_gcs)
                    except Exception:
                        ok = False

                if not ok:
                    log('DRONE-SIG', 'verification of GCS seed failed; aborting')
                    return None

                # generate own seed and signature, send
                seed_drone = os.urandom(AES_KEY_LEN)
                try:
                    sig_drone = sig.sign(seed_drone)
                except Exception:
                    sig_drone = sig.sign_message(seed_drone)
                s.sendall(len(seed_drone).to_bytes(4, 'big') + seed_drone + len(sig_drone).to_bytes(4, 'big') + sig_drone)

                log('DRONE-SIG', 'signature handshake succeeded')
                return hashlib.sha256(seed_gcs + seed_drone).digest()[:AES_KEY_LEN]
            except Exception as e:
                log('DRONE-SIG', 'liboqs signature handshake failed:', e)

        # Fallback: receive random r, send our random
        plen = int.from_bytes(s.recv(4), 'big')
        r = s.recv(plen)
        other = os.urandom(AES_KEY_LEN)
        s.sendall(len(other).to_bytes(4, 'big') + other)
        key = derive_aes_key_fallback(r, other)
        log('DRONE-SIG', 'derived AES key using insecure fallback')
        return key


def encrypt_message(aesgcm: Optional[object], key: bytes, plaintext: bytes) -> bytes:
    if AESGCM is None:
        raise RuntimeError('AESGCM not available')
    nonce = os.urandom(NONCE_IV_SIZE)
    aes = AESGCM(key)
    ct = aes.encrypt(nonce, plaintext, None)
    # prefix magic so recipients can drop non-matching packets quickly
    return MAGIC_BYTES + nonce + ct


def decrypt_message(aesgcm: Optional[object], key: bytes, encrypted: bytes) -> Optional[bytes]:
    if AESGCM is None:
        raise RuntimeError('AESGCM not available')
    if len(encrypted) < NONCE_IV_SIZE:
        return None
    # fast check for magic header
    if not encrypted.startswith(MAGIC_BYTES):
        return None
    payload = encrypted[len(MAGIC_BYTES):]
    if len(payload) < NONCE_IV_SIZE:
        return None
    nonce = payload[:NONCE_IV_SIZE]
    ct = payload[NONCE_IV_SIZE:]
    aes = AESGCM(key)
    try:
        return aes.decrypt(nonce, ct, None)
    except Exception:
        return None


def run_proxy(role: str, algo: str, public_host: str = '0.0.0.0', public_port: Optional[int] = None,
              local_bind: str = '127.0.0.1', local_port: int = 14550, gcs_host: str = '127.0.0.1'):
    """Run a minimal single-port proxy.

    role: 'gcs' or 'drone'
    algo: textual algorithm tag (used to select KEM name); mapping handled below
    """
    prefix = f"{algo.upper()}:{role.upper()}"
    # Mapping from repo shorthand to liboqs algorithm identifiers (preferred names used in this repo)
    kem_map = {
        # Kyber variants (KEM)
        'k512': 'ML-KEM-512',
        'k768': 'ML-KEM-768',
        'k1024': 'ML-KEM-1024',
        'kyber_512': 'ML-KEM-512',
        'kyber_768': 'ML-KEM-768',
        'kyber_1024': 'ML-KEM-1024',
        # Generic fallbacks
        'kyber': 'ML-KEM-768',
    }

    # Signature algorithm mapping (used for logging / future use)
    sig_map = {
        'dilithium2': 'Dilithium2',
        'dilithium3': 'Dilithium3',
        'dilithium5': 'Dilithium5',
        # liboqs often exposes Dilithium as 'Dilithium2', etc. Adjusted names above.
        'falcon512': 'Falcon-512',
        'falcon1024': 'Falcon-1024',
        # SPHINCS+ variants — many liboqs bindings use names like 'SPHINCS+-SHA2-256f'
        'sphincs_haraka_128f': 'SPHINCS+-HARAKA-128f',
        'sphincs_haraka_256f': 'SPHINCS+-HARAKA-256f',
        'sphincs_sha2_128f': 'SPHINCS+-SHA2-128f',
        'sphincs_sha2_256f': 'SPHINCS+-SHA2-256f',
    }

    def resolve_kem_name(requested: str) -> str:
        # Prefer explicit mapping; if liboqs is available, try to pick a matching enabled mechanism
        name = kem_map.get(requested, kem_map.get(requested.lower(), 'ML-KEM-768'))
        if USING_LIBOQS and oqs is not None:
            try:
                # prefer user-facing API to list enabled KEMs; handle different binding names
                enabled = []
                if hasattr(oqs, 'get_enabled_KEMs'):
                    enabled = oqs.get_enabled_KEMs()
                elif hasattr(oqs, 'get_enabled_kems'):
                    enabled = oqs.get_enabled_kems()
                # Try exact match first
                if name in enabled:
                    return name
                # Try looser matches (case-insensitive substring)
                lenabled = [e.lower() for e in enabled]
                for e in enabled:
                    if requested.lower() in e.lower():
                        log('KEM-RESOLVE', f"mapping {requested} -> enabled kem {e}")
                        return e
                # fallback to first enabled KEM
                if enabled:
                    log('KEM-RESOLVE', f"requested {requested} not found; using first enabled kem {enabled[0]}")
                    return enabled[0]
            except Exception as e:
                log('KEM-RESOLVE', 'could not query liboqs enabled KEMs:', e)
        return name

    kem_name = resolve_kem_name(algo)
    sig_name = sig_map.get(algo)

    if public_port is None:
        public_port = 5821 if role == 'gcs' else 5811

    # Key exchange: if algo maps to a signature scheme, use signature-handshake, otherwise use KEM
    if sig_name:
        log(prefix, 'using signature handshake', sig_name)
        if role == 'gcs':
            aes_key = tcp_signature_handshake_gcs(public_host, sig_name, PORT_KEY_EXCHANGE)
        else:
            aes_key = tcp_signature_handshake_drone(gcs_host, sig_name, PORT_KEY_EXCHANGE)
        if aes_key is None:
            log(prefix, 'signature handshake failed; falling back to KEM')
            if role == 'gcs':
                aes_key = tcp_key_exchange_gcs(public_host, kem_name, PORT_KEY_EXCHANGE)
            else:
                aes_key = tcp_key_exchange_drone(gcs_host, kem_name, PORT_KEY_EXCHANGE)
    else:
        if role == 'gcs':
            aes_key = tcp_key_exchange_gcs(public_host, kem_name, PORT_KEY_EXCHANGE)
        else:
            aes_key = tcp_key_exchange_drone(gcs_host, kem_name, PORT_KEY_EXCHANGE)

    log(prefix, 'AES key length', len(aes_key))

    # UDP sockets
    public_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    public_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    public_sock.bind((public_host, public_port))
    log(prefix, f'public UDP bound on {public_host}:{public_port}')

    local_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    local_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    local_sock.bind((local_bind, local_port))
    log(prefix, f'local plain UDP bound on {local_bind}:{local_port}')

    session = {'addr': None, 'last_seen': 0}

    # Send a small UDP probe to the peer public port to seed remote session addresses
    try:
        if role == 'gcs':
            peer_port = 5811
            peer_host = gcs_host  # in typical test this is localhost
        else:
            peer_port = 5821
            peer_host = gcs_host
        public_sock.sendto(b'probe', (peer_host, peer_port))
        log(prefix, f'sent probe to peer public {(peer_host, peer_port)}')
    except Exception as e:
        log(prefix, 'probe send failed', e)

    def public_recv_loop():
        while True:
            try:
                data, addr = public_sock.recvfrom(BUFFER_SIZE)
                session['addr'] = addr
                session['last_seen'] = time.time()
                pt = decrypt_message(AESGCM, aes_key, data)
                if pt is None:
                    log(prefix, 'decrypt failed from', addr)
                    continue
                # forward to local app (assume local app at local_bind:local_port)
                local_sock.sendto(pt, (local_bind, local_port))
                log(prefix, f'forwarded {len(pt)} bytes plaintext to local app')
            except Exception as e:
                log(prefix, 'public_recv_loop error', e)
                time.sleep(0.5)

    def local_recv_loop():
        while True:
            try:
                data, src = local_sock.recvfrom(BUFFER_SIZE)
                # send to last known remote addr
                addr = session.get('addr')
                if addr is None or (time.time() - session.get('last_seen', 0)) > SESSION_TIMEOUT:
                    log(prefix, 'no remote addr known; dropping packet')
                    continue
                out = encrypt_message(AESGCM, aes_key, data)
                public_sock.sendto(out, addr)
                log(prefix, f'sent {len(out)} bytes encrypted to {addr}')
            except Exception as e:
                log(prefix, 'local_recv_loop error', e)
                time.sleep(0.5)

    t1 = threading.Thread(target=public_recv_loop, daemon=True)
    t2 = threading.Thread(target=local_recv_loop, daemon=True)
    t1.start()
    t2.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        log(prefix, 'shutting down')
        public_sock.close(); local_sock.close()


def cli_main():
    p = argparse.ArgumentParser()
    p.add_argument('--role', choices=['gcs', 'drone'], required=True)
    p.add_argument('--algo', default='k768')
    p.add_argument('--public-host', default='0.0.0.0')
    p.add_argument('--public-port', type=int)
    p.add_argument('--local-port', type=int, default=14550)
    p.add_argument('--gcs-host', default='127.0.0.1')
    args = p.parse_args()
    run_proxy(args.role, args.algo, public_host=args.public_host, public_port=args.public_port,
              local_port=args.local_port, gcs_host=args.gcs_host)


if __name__ == '__main__':
    cli_main()
