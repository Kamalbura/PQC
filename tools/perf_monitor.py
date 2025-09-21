#!/usr/bin/env python3
"""Performance monitor that logs PPS, CPU%, memory%, and CPU temperature once per second.

Listens for decrypted plaintext packets on the drone plaintext port and logs metrics to a CSV.
"""
import argparse
import socket
import time
import os
import sys
import csv
from datetime import datetime

try:
    import psutil
except Exception:
    print('perf_monitor requires psutil (pip install psutil)')
    raise

# try to import central ip_config from drone/ if present
ROOT = os.path.dirname(os.path.dirname(__file__))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)
try:
    from drone.ip_config import DRONE_HOST, PORT_DRONE_FORWARD_DECRYPTED_CMD
except Exception:
    DRONE_HOST = '127.0.0.1'
    PORT_DRONE_FORWARD_DECRYPTED_CMD = 5812


def find_proxy_pid(name_hint: str = 'async_drone.py') -> int:
    for p in psutil.process_iter(['pid', 'name', 'cmdline']):
        try:
            cmd = ' '.join(p.info.get('cmdline') or [])
            if name_hint in cmd:
                return p.info['pid']
        except Exception:
            continue
    return -1


def read_cpu_temp() -> float:
    # Linux path; return -1.0 on unsupported platforms
    try:
        with open('/sys/class/thermal/thermal_zone0/temp', 'r') as f:
            v = int(f.read().strip())
            return v / 1000.0
    except Exception:
        return -1.0


def main():
    p = argparse.ArgumentParser(description='perf_monitor - log PPS and system metrics')
    p.add_argument('--algo', required=True, help='algorithm name (used in output filename)')
    p.add_argument('--pid-hint', default='async_drone.py', help='process name hint to find proxy PID')
    p.add_argument('--host', default=DRONE_HOST, help='host to bind and listen for plaintext')
    p.add_argument('--port', type=int, default=PORT_DRONE_FORWARD_DECRYPTED_CMD, help='port to bind and listen')
    args = p.parse_args()

    timestamp = datetime.utcnow().strftime('%Y%m%d-%H%M%S')
    out_name = f'results_{args.algo}_{timestamp}.csv'

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((args.host, args.port))
    sock.settimeout(1.0)

    pid = find_proxy_pid(args.pid_hint)
    proc = psutil.Process(pid) if pid != -1 else None
    if proc is None:
        print('Warning: proxy process not found; CPU/mem metrics will be unavailable until process starts')

    print(f'perf_monitor listening on {(args.host, args.port)} output={out_name} pid={pid}')

    # buffer counters
    received = 0
    start = time.time()

    with open(out_name, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(['timestamp_utc', 'pps', 'cpu_percent', 'mem_percent', 'temp_c'])

        try:
            while True:
                tick_start = time.time()
                # count packets for 1 second
                received = 0
                end_tick = tick_start + 1.0
                while time.time() < end_tick:
                    try:
                        data, addr = sock.recvfrom(65535)
                        received += 1
                    except socket.timeout:
                        # no packet this short interval
                        pass
                # metrics
                cpu_percent = proc.cpu_percent(interval=None) if proc else -1.0
                mem_percent = proc.memory_percent() if proc else -1.0
                temp_c = read_cpu_temp()
                ts = datetime.utcnow().isoformat()
                writer.writerow([ts, received, cpu_percent, mem_percent, temp_c])
                csvfile.flush()
                print(f'[{ts}] pps={received} cpu%={cpu_percent} mem%={mem_percent} temp={temp_c}')
        except KeyboardInterrupt:
            print('perf_monitor stopped by user')
        finally:
            sock.close()


if __name__ == '__main__':
    main()
