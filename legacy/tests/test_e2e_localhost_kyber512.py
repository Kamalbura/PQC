#!/usr/bin/env python3
"""
End-to-end localhost test for the proxy pair using Kyber-512 (transport-only AES channel).
- Starts GCS proxy (gcs_kyber_512.py) in a subprocess
- Starts Drone proxy (drone_kyber_512.py) in a subprocess
- Sends one plaintext command into GCS plaintext port (5810)
- Sends one plaintext telemetry into Drone plaintext port (5820)
- Asserts the decrypted outputs are received on the forward ports (5812, 5822)
Assumes both ip_config.py files use 127.0.0.1 and ports 5800/5810-12/5820-22.
"""
import os
import sys
import time
import socket
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GCS = ROOT / 'gcs' / 'gcs_kyber_512.py'
DRONE = ROOT / 'drone' / 'drone_kyber_512.py'

GCS_HOST = '127.0.0.1'
DRONE_HOST = '127.0.0.1'
PORT_KEY_EXCHANGE = 5800
PORT_GCS_LISTEN_PLAINTEXT_CMD = 5810
PORT_DRONE_FORWARD_DECRYPTED_CMD = 5812
PORT_DRONE_LISTEN_PLAINTEXT_TLM = 5820
PORT_GCS_FORWARD_DECRYPTED_TLM = 5822


def udp_send(msg: bytes, host: str, port: int):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.sendto(msg, (host, port))
    s.close()


def udp_recv_with_timeout(host: str, port: int, timeout: float = 5.0):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((host, port))
    s.settimeout(timeout)
    try:
        data, _ = s.recvfrom(65535)
        return data
    finally:
        s.close()


def wait_for_port_open(host: str, port: int, timeout: float = 5.0):
    end = time.time() + timeout
    while time.time() < end:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return True
        except Exception:
            time.sleep(0.1)
    return False


def main():
    # Ensure scripts exist
    assert GCS.exists(), f"Missing {GCS}"
    assert DRONE.exists(), f"Missing {DRONE}"

    # Launch GCS then Drone
    env = os.environ.copy()
    gcs_proc = subprocess.Popen([sys.executable, str(GCS)], cwd=str(GCS.parent), env=env)
    # Wait a bit for GCS to start listening on 5800
    ok = wait_for_port_open(GCS_HOST, PORT_KEY_EXCHANGE, timeout=8.0)
    if not ok:
        gcs_proc.kill(); gcs_proc.wait()
        print('[FAIL] GCS key-exchange port did not open in time')
        return 1

    drone_proc = subprocess.Popen([sys.executable, str(DRONE)], cwd=str(DRONE.parent), env=env)

    # Give a moment for KEM handshake
    time.sleep(2.0)

    # Send a plaintext command into GCS plaintext port (5810)
    cmd_msg = b'CMD:LAND'
    udp_send(cmd_msg, GCS_HOST, PORT_GCS_LISTEN_PLAINTEXT_CMD)

    # Expect decrypted command to appear at drone forward port (5812)
    try:
        got_cmd = udp_recv_with_timeout(DRONE_HOST, PORT_DRONE_FORWARD_DECRYPTED_CMD, timeout=6.0)
        assert got_cmd == cmd_msg, f"Decrypted command mismatch: {got_cmd!r}"
        print('[PASS] Kyber-512 Command flow GCS->Drone e2e OK')
    except Exception as e:
        print('[FAIL] Kyber-512 Command flow:', e)
        drone_proc.kill(); gcs_proc.kill(); drone_proc.wait(); gcs_proc.wait()
        return 1

    # Send a plaintext telemetry into Drone plaintext port (5820)
    tlm_msg = b'TLM:BAT(90%)'
    udp_send(tlm_msg, DRONE_HOST, PORT_DRONE_LISTEN_PLAINTEXT_TLM)

    # Expect decrypted telemetry at GCS forward port (5822)
    try:
        got_tlm = udp_recv_with_timeout(GCS_HOST, PORT_GCS_FORWARD_DECRYPTED_TLM, timeout=6.0)
        assert got_tlm == tlm_msg, f"Decrypted telemetry mismatch: {got_tlm!r}"
        print('[PASS] Kyber-512 Telemetry flow Drone->GCS e2e OK')
    except Exception as e:
        print('[FAIL] Kyber-512 Telemetry flow:', e)
        drone_proc.kill(); gcs_proc.kill(); drone_proc.wait(); gcs_proc.wait()
        return 1

    # Clean up
    drone_proc.terminate(); gcs_proc.terminate()
    try:
        drone_proc.wait(timeout=2.0)
    except subprocess.TimeoutExpired:
        drone_proc.kill(); drone_proc.wait()
    try:
        gcs_proc.wait(timeout=2.0)
    except subprocess.TimeoutExpired:
        gcs_proc.kill(); gcs_proc.wait()

    print('Summary: Kyber-512 e2e localhost test PASS')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
