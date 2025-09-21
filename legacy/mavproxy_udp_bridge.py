#!/usr/bin/env python3
"""
mavproxy_udp_bridge.py

Lightweight MAVLink UDP bridge (MAVProxy-style) for testing PQC proxies.

Usage examples:
  # run on drone side (uses drone/ip_config.py defaults)
  python mavproxy_udp_bridge.py --side drone

  # run on gcs side and override ports
  python mavproxy_udp_bridge.py --side gcs --telemetry-send-port 5822 --telemetry-recv-port 5821 --cmd-send-port 5812 --cmd-recv-port 5811

This bridge creates two UDP forwarding threads:
 - Telemetry path: receives plaintext telemetry from flight controller and forwards to GCS proxy (encrypted path uses other ports)
 - Command path: receives plaintext commands from GCS app and forwards to flight controller

Prints READY when both threads are started.
"""

import argparse
import socket
import threading
import time
import sys

def load_ip_config(side: str):
    if side == 'drone':
        try:
            from drone.ip_config import *
        except Exception:
            raise
    else:
        try:
            from gcs.ip_config import *
        except Exception:
            raise
    # Return a dict of commonly used ports/hosts
    return globals()

def udp_forward(bind_host, bind_port, dest_host, dest_port, name=None):
    name = name or f"{bind_host}:{bind_port}->{dest_host}:{dest_port}"
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((bind_host, bind_port))
    print(f"[BRIDGE] {name} listening")
    try:
        while True:
            data, addr = sock.recvfrom(65535)
            # simple forward
            sock.sendto(data, (dest_host, dest_port))
    except Exception as e:
        print(f"[BRIDGE] {name} exception: {e}")
    finally:
        sock.close()

def main():
    p = argparse.ArgumentParser(description='MAVProxy UDP bridge for PQC testing')
    p.add_argument('--side', choices=['drone','gcs'], required=True, help='Which side this bridge runs on')
    p.add_argument('--telemetry-send-port', type=int, help='Port to send telemetry to (default from ip_config)')
    p.add_argument('--telemetry-recv-port', type=int, help='Port to receive telemetry from (default from ip_config)')
    p.add_argument('--cmd-send-port', type=int, help='Port to send commands to (default from ip_config)')
    p.add_argument('--cmd-recv-port', type=int, help='Port to receive commands from (default from ip_config)')
    p.add_argument('--host', help='Host to bind to (defaults to DRONE_HOST or GCS_HOST)')
    args = p.parse_args()

    # Load config from the appropriate ip_config
    cfg = load_ip_config(args.side)

    if args.side == 'drone':
        bind_host = args.host or cfg.get('DRONE_HOST')
        # Telemetry: DRONE -> GCS (DRONE sends plaintext telemetry to PORT_DRONE_LISTEN_PLAINTEXT_TLM)
        telemetry_recv_port = args.telemetry_recv_port or cfg.get('PORT_DRONE_LISTEN_PLAINTEXT_TLM')
        telemetry_send_port = args.telemetry_send_port or cfg.get('PORT_GCS_FORWARD_DECRYPTED_TLM')
        # Commands: GCS -> DRONE (GCS sends plaintext commands to PORT_GCS_LISTEN_PLAINTEXT_CMD)
        cmd_recv_port = args.cmd_recv_port or cfg.get('PORT_GCS_LISTEN_PLAINTEXT_CMD')
        cmd_send_port = args.cmd_send_port or cfg.get('PORT_DRONE_FORWARD_DECRYPTED_CMD')
        dest_host_for_telemetry = cfg.get('GCS_HOST')
        dest_host_for_cmds = cfg.get('DRONE_HOST')
    else:
        bind_host = args.host or cfg.get('GCS_HOST')
        telemetry_recv_port = args.telemetry_recv_port or cfg.get('PORT_GCS_FORWARD_DECRYPTED_TLM')
        telemetry_send_port = args.telemetry_send_port or cfg.get('PORT_DRONE_LISTEN_PLAINTEXT_TLM')
        cmd_recv_port = args.cmd_recv_port or cfg.get('PORT_GCS_LISTEN_PLAINTEXT_CMD')
        cmd_send_port = args.cmd_send_port or cfg.get('PORT_GCS_FORWARD_DECRYPTED_TLM')
        dest_host_for_telemetry = cfg.get('DRONE_HOST')
        dest_host_for_cmds = cfg.get('GCS_HOST')

    threads = []

    t1 = threading.Thread(target=udp_forward, args=(bind_host, telemetry_recv_port, dest_host_for_telemetry, telemetry_send_port, 'telemetry'), daemon=True)
    threads.append(t1)
    t2 = threading.Thread(target=udp_forward, args=(bind_host, cmd_recv_port, dest_host_for_cmds, cmd_send_port, 'commands'), daemon=True)
    threads.append(t2)

    for t in threads:
        t.start()

    print("READY")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("Shutting down bridge...")

if __name__ == '__main__':
    main()
