#!/usr/bin/env python3
"""High-rate UDP packet generator for proxy benchmarking.

Sends repeated fake MAVLink-like packets to the GCS plaintext command port.
"""
import argparse
import socket
import time
import os
import sys

# try to import central ip_config from gcs/ if present
ROOT = os.path.dirname(os.path.dirname(__file__))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)
try:
    from gcs.ip_config import GCS_HOST, PORT_GCS_LISTEN_PLAINTEXT_CMD
except Exception:
    # sensible defaults for loopback testing
    GCS_HOST = '127.0.0.1'
    PORT_GCS_LISTEN_PLAINTEXT_CMD = 5810

FAKE_MAVLINK_PKT = b"\xfe\x09\x01\x01\x00\x00HELLO_MAVLINK\x00"  # small fake packet


def main():
    p = argparse.ArgumentParser(description='packet_blaster - UDP flooder for proxy benchmarking')
    p.add_argument('--rate', type=int, required=True, help='packets per second')
    p.add_argument('--duration', type=int, required=True, help='duration seconds')
    p.add_argument('--host', default=GCS_HOST, help='target host')
    p.add_argument('--port', type=int, default=PORT_GCS_LISTEN_PLAINTEXT_CMD, help='target port')
    args = p.parse_args()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    dest = (args.host, args.port)
    total_sent = 0

    interval = 1.0 / max(1, args.rate)
    end_time = time.time() + args.duration
    next_send = time.time()

    try:
        while time.time() < end_time:
            now = time.time()
            if now >= next_send:
                sock.sendto(FAKE_MAVLINK_PKT, dest)
                total_sent += 1
                next_send += interval
            else:
                time.sleep(min(0.001, next_send - now))
    except KeyboardInterrupt:
        pass
    finally:
        sock.close()

    print(f'packet_blaster finished: sent={total_sent} target={dest} rate={args.rate} duration={args.duration}')


if __name__ == '__main__':
    main()
