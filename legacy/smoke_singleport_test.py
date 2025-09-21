"""Smoke test for single-port proxies (loopback).

Starts sgcs/gcs_kyber_512.py and sdrone/drone_kyber_512.py and verifies a short plaintext roundtrip.
Also tests signature handshake using dilithium3 wrappers.

This script is best-effort: if liboqs is missing it will still run but use insecure fallback keys.
"""
import time
import socket
import sys
import os
from multiprocessing import Process

# ensure repo root is on sys.path so imports work when running from legacy/
ROOT = os.path.dirname(os.path.dirname(__file__))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from async_proxy import run_proxy_async
from singleport_common import MAGIC_BYTES


def start_proxy(role, algo, public_host='127.0.0.1', public_port=None, local_in_port=None, local_out_port=None, gcs_host='127.0.0.1'):
    # wrapper that calls the async proxy runner; runs until terminated
    public_port = public_port or (5821 if role == 'gcs' else 5811)
    # run_proxy_async is coroutine; run it in a fresh event loop inside the process
    import asyncio
    asyncio.run(run_proxy_async(role, algo, public_host, public_port, '127.0.0.1', local_in_port, local_out_port, gcs_host))


def run_pair_inproc(gcs_algo, drone_algo, timeout=8):
    # Use research port defaults for loopback
    GCS_PUBLIC = 5821
    GCS_LOCAL_PLAIN = 5822
    DRONE_PUBLIC = 5811
    DRONE_LOCAL_PLAIN = 5812

    # note: local_in_port is where proxy listens for plaintext FROM the local app
    # local_out_port is where proxy sends decrypted plaintext TO the local app
    gcs_p = Process(target=start_proxy, args=('gcs', gcs_algo, '127.0.0.1', GCS_PUBLIC, GCS_LOCAL_PLAIN, GCS_LOCAL_PLAIN+1, '127.0.0.1'))
    drone_p = Process(target=start_proxy, args=('drone', drone_algo, '127.0.0.1', DRONE_PUBLIC, DRONE_LOCAL_PLAIN+1, DRONE_LOCAL_PLAIN, '127.0.0.1'))
    gcs_p.start(); drone_p.start()

    try:
        time.sleep(2)  # wait for key exchanges to complete

        # Allow proxies' internal probe to seed remote session mapping
        time.sleep(0.2)

        # Send a test plaintext to GCS local decrypted port (127.0.0.1:GCS_LOCAL_PLAIN)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        test_msg = b'hello-singleport-test'
        sock.sendto(test_msg, ('127.0.0.1', GCS_LOCAL_PLAIN))

        # Listen briefly on the drone's decrypted forward port
        recv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        recv.bind(('127.0.0.1', DRONE_LOCAL_PLAIN))
        recv.settimeout(timeout)
        try:
            data, addr = recv.recvfrom(2048)
            print('Received at drone local port:', data, 'from', addr)
            ok = (data == test_msg)
        except socket.timeout:
            print('Timeout waiting for drone to receive forwarded plaintext')
            ok = False

        return ok
    finally:
        gcs_p.terminate(); drone_p.terminate()
        gcs_p.join(); drone_p.join()


if __name__ == '__main__':
    print('Testing KEM (Kyber-512) pair in-process...')
    ok1 = run_pair_inproc('k512', 'k512')
    print('KEM test OK=', ok1)

    print('Testing signature handshake (Dilithium3) pair in-process...')
    ok2 = run_pair_inproc('dilithium3', 'dilithium3')
    print('Signature test OK=', ok2)

    if ok1 and ok2:
        print('SMOKE TEST PASSED')
        sys.exit(0)
    else:
        print('SMOKE TEST FAILED')
        sys.exit(2)
