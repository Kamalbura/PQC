#!/usr/bin/env python3
"""Async single-port proxy (asyncio) that forwards between a single public UDP socket and a pair of local UDP ports.

Uses existing handshake functions from singleport_common for key derivation.

This module exposes run_proxy_async(role, algo, public_host, public_port, local_bind, local_in_port, local_out_port, gcs_host)
which runs until cancelled. It offloads crypto to the default thread pool using loop.run_in_executor to avoid blocking the event loop.
"""
import asyncio
import socket
import time
import hashlib
from typing import Optional, Tuple

from singleport_common import (
    tcp_key_exchange_gcs,
    tcp_key_exchange_drone,
    tcp_signature_handshake_gcs,
    tcp_signature_handshake_drone,
    encrypt_message,
    decrypt_message,
    PORT_KEY_EXCHANGE,
    NONCE_IV_SIZE,
    AES_KEY_LEN,
    BUFFER_SIZE,
    MAGIC_BYTES,
)

# Prefer centralized project-level IP config for ports if present
try:
    from project_ip_config import (
        PORT_GCS_LISTEN_ENCRYPTED_TLM, PORT_GCS_LISTEN_PLAINTEXT_CMD, PORT_GCS_FORWARD_DECRYPTED_TLM,
        PORT_DRONE_LISTEN_ENCRYPTED_CMD, PORT_DRONE_LISTEN_PLAINTEXT_TLM, PORT_DRONE_FORWARD_DECRYPTED_CMD,
    )
except Exception:
    # fallback defaults matching earlier behavior
    PORT_GCS_LISTEN_ENCRYPTED_TLM = 5821
    PORT_GCS_LISTEN_PLAINTEXT_CMD = 5810
    PORT_GCS_FORWARD_DECRYPTED_TLM = 5822
    PORT_DRONE_LISTEN_ENCRYPTED_CMD = 5811
    PORT_DRONE_LISTEN_PLAINTEXT_TLM = 5820
    PORT_DRONE_FORWARD_DECRYPTED_CMD = 5812


async def run_proxy_async(role: str, algo: str,
                          public_host: str = '0.0.0.0', public_port: int = 5821,
                          local_bind: str = '127.0.0.1',
                          local_in_port: int = 14550, local_out_port: int = 14551,
                          gcs_host: str = '127.0.0.1'):
    """Async single-port proxy.

    local_in_port: proxy listens here for plaintext from the local app (e.g., MAVProxy input).
    local_out_port: proxy sends decrypted plaintext to this address (local app should bind to receive).
    """
    prefix = f"ASYNC-{algo.upper()}:{role.upper()}"

    loop = asyncio.get_running_loop()

    # Do key exchange synchronously (blocking) before entering event loop tasks
    if algo.lower().startswith('dilithium') or algo.lower().startswith('falcon') or algo.lower().startswith('sphincs'):
        # signature handshake
        if role == 'gcs':
            # Bind signature server on all interfaces to avoid invalid-address errors
            aes_key = tcp_signature_handshake_gcs('0.0.0.0', algo.title(), PORT_KEY_EXCHANGE)
        else:
            aes_key = tcp_signature_handshake_drone(gcs_host, algo.title(), PORT_KEY_EXCHANGE)
        if aes_key is None:
            # fall back to KEM
            if role == 'gcs':
                aes_key = tcp_key_exchange_gcs('0.0.0.0', 'ML-KEM-768', PORT_KEY_EXCHANGE)
            else:
                aes_key = tcp_key_exchange_drone(gcs_host, 'ML-KEM-768', PORT_KEY_EXCHANGE)
    else:
        # KEM flow (map a simple mapping here)
        kem_name = 'ML-KEM-512' if '512' in algo else ('ML-KEM-1024' if '1024' in algo else 'ML-KEM-768')
        if role == 'gcs':
            # Listen on all interfaces for KEX
            aes_key = tcp_key_exchange_gcs('0.0.0.0', kem_name, PORT_KEY_EXCHANGE)
        else:
            aes_key = tcp_key_exchange_drone(gcs_host, kem_name, PORT_KEY_EXCHANGE)

    print(f'[{prefix}] AES key length', len(aes_key))

    # Setup sockets in non-blocking mode
    public_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    public_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    public_sock.setblocking(False)
    try:
        public_sock.bind((public_host, public_port))
    except OSError as e:
        # If binding to specific IP fails (not present), fall back to 0.0.0.0
        print(f'[{prefix}] public bind failed on {public_host}:{public_port} -> {e}; falling back to 0.0.0.0')
        public_sock.bind(('0.0.0.0', public_port))
    print(f'[{prefix}] public UDP bound on {public_host}:{public_port}')

    local_in_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    local_in_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    local_in_sock.setblocking(False)
    local_in_sock.bind((local_bind, local_in_port))
    print(f'[{prefix}] local-in UDP bound on {local_bind}:{local_in_port}')

    # Create a local-out socket used to send decrypted plaintext to the local app
    local_out_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    local_out_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    local_out_sock.setblocking(False)
    # not binding so OS chooses ephemeral port for outgoing
    local_out_addr = (local_bind, local_out_port)
    print(f'[{prefix}] local-out address set to {local_out_addr}')

    session = {'addr': None, 'last_seen': 0}

    async def public_recv_loop():
        while True:
            try:
                data, addr = await loop.sock_recvfrom(public_sock, BUFFER_SIZE)
                print(f'[{prefix}] public_recv_loop received {len(data)} bytes from {addr}')
                session['addr'] = addr
                session['last_seen'] = time.time()

                # quick magic check before offloading expensive crypto
                if not data.startswith(MAGIC_BYTES):
                    print(f'[{prefix}] dropping non-magic packet from {addr} len={len(data)} prefix={data[:8].hex()}')
                    continue
                # Decrypt in executor to avoid blocking; handle cancellation cleanly
                try:
                    plaintext = await loop.run_in_executor(None, decrypt_message, None, aes_key, data)
                except asyncio.CancelledError:
                    # shutting down
                    print(f'[{prefix}] public_recv_loop decrypt cancelled')
                    break
                except Exception as e:
                    print(f'[{prefix}] decrypt executor error', e)
                    continue
                if plaintext is None:
                    print(f'[{prefix}] decrypt failed from {addr}; cipher-prefix={data[:16].hex()}')
                    continue
                # Forward to local app's out address using local_out_sock
                await loop.sock_sendto(local_out_sock, plaintext, local_out_addr)
                print(f'[{prefix}] forwarded {len(plaintext)} bytes plaintext to local app {local_out_addr}')
            except asyncio.CancelledError:
                break
            except Exception as e:
                print(f'[{prefix}] public_recv_loop error', e)
                await asyncio.sleep(0.01)

    async def local_recv_loop():
        while True:
            try:
                data, addr = await loop.sock_recvfrom(local_in_sock, BUFFER_SIZE)
                print(f'[{prefix}] local_recv_loop received {len(data)} bytes from {addr}')
                # encrypt in executor (encrypt_message prefixes MAGIC_BYTES)
                try:
                    encrypted = await loop.run_in_executor(None, encrypt_message, None, aes_key, data)
                except asyncio.CancelledError:
                    print(f'[{prefix}] local_recv_loop encrypt cancelled')
                    break
                except Exception as e:
                    print(f'[{prefix}] encrypt executor error', e)
                    continue
                addr_remote = session.get('addr')
                print(f'[{prefix}] current remote addr={addr_remote} last_seen={session.get("last_seen")}')
                if addr_remote is None or (time.time() - session.get('last_seen', 0)) > 120:
                    # send to peer derived from role
                    peer_port = PORT_DRONE_LISTEN_ENCRYPTED_CMD if role == 'gcs' else PORT_GCS_LISTEN_ENCRYPTED_TLM
                    addr_remote = (gcs_host, peer_port)
                    print(f'[{prefix}] no recent remote; using peer default {addr_remote}')
                await loop.sock_sendto(public_sock, encrypted, addr_remote)
                print(f'[{prefix}] sent {len(encrypted)} bytes encrypted to {addr_remote}')
            except asyncio.CancelledError:
                break
            except Exception as e:
                print(f'[{prefix}] local_recv_loop error', e)
                await asyncio.sleep(0.01)

    # seed with a probe to help establish session mapping
    try:
        # send a valid encrypted empty payload (encrypt_message prefixes MAGIC_BYTES)
        try:
            probe_ct = await loop.run_in_executor(None, encrypt_message, None, aes_key, b'')
        except asyncio.CancelledError:
            probe_ct = None
        except Exception as e:
            print(f'[{prefix}] probe encrypt error', e)
            probe_ct = None
        if probe_ct:
            try:
                # if I'm GCS, my peer is the drone command listener (5811). If I'm Drone, my peer is GCS telemetry listener (5821)
                peer_port = PORT_DRONE_LISTEN_ENCRYPTED_CMD if role == 'gcs' else PORT_GCS_LISTEN_ENCRYPTED_TLM
                await loop.sock_sendto(public_sock, probe_ct, (gcs_host, peer_port))
            except Exception:
                # best-effort send; ignore
                pass
    except Exception:
        pass

    # Run tasks
    tasks = [asyncio.create_task(public_recv_loop()), asyncio.create_task(local_recv_loop())]
    try:
        await asyncio.gather(*tasks)
    except asyncio.CancelledError:
        for t in tasks:
            t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


def cli_main():
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument('--role', choices=['gcs', 'drone'], required=True)
    p.add_argument('--algo', default='k768')
    p.add_argument('--public-host', default='0.0.0.0')
    p.add_argument('--public-port', type=int, default=None)
    p.add_argument('--local-in-port', type=int, default=14550)
    p.add_argument('--local-out-port', type=int, default=14551)
    p.add_argument('--gcs-host', default='127.0.0.1')
    args = p.parse_args()
    public_port = args.public_port or (5821 if args.role == 'gcs' else 5811)
    asyncio.run(run_proxy_async(args.role, args.algo, args.public_host, public_port, '127.0.0.1', args.local_in_port, args.local_out_port, args.gcs_host))


if __name__ == '__main__':
    cli_main()
