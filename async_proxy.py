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
            aes_key = tcp_signature_handshake_gcs(public_host, algo.title(), PORT_KEY_EXCHANGE)
        else:
            aes_key = tcp_signature_handshake_drone(gcs_host, algo.title(), PORT_KEY_EXCHANGE)
        if aes_key is None:
            # fall back to KEM
            if role == 'gcs':
                aes_key = tcp_key_exchange_gcs(public_host, 'ML-KEM-768', PORT_KEY_EXCHANGE)
            else:
                aes_key = tcp_key_exchange_drone(gcs_host, 'ML-KEM-768', PORT_KEY_EXCHANGE)
    else:
        # KEM flow (map a simple mapping here)
        kem_name = 'ML-KEM-512' if '512' in algo else ('ML-KEM-1024' if '1024' in algo else 'ML-KEM-768')
        if role == 'gcs':
            aes_key = tcp_key_exchange_gcs(public_host, kem_name, PORT_KEY_EXCHANGE)
        else:
            aes_key = tcp_key_exchange_drone(gcs_host, kem_name, PORT_KEY_EXCHANGE)

    print(f'[{prefix}] AES key length', len(aes_key))

    # Setup sockets in non-blocking mode
    public_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    public_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    public_sock.setblocking(False)
    public_sock.bind((public_host, public_port))
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
                # Decrypt in executor to avoid blocking
                plaintext = await loop.run_in_executor(None, decrypt_message, None, aes_key, data)
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
                encrypted = await loop.run_in_executor(None, encrypt_message, None, aes_key, data)
                addr_remote = session.get('addr')
                print(f'[{prefix}] current remote addr={addr_remote} last_seen={session.get("last_seen")}')
                if addr_remote is None or (time.time() - session.get('last_seen', 0)) > 120:
                    print(f'[{prefix}] no remote addr known; dropping packet')
                    continue
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
        probe_ct = await loop.run_in_executor(None, encrypt_message, None, aes_key, b'')
        await loop.sock_sendto(public_sock, probe_ct, (gcs_host, 5811 if role == 'gcs' else 5821))
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
