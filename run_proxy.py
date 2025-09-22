#!/usr/bin/env python3
"""Unified role-aware proxy runner with benchmark mode.

Modes:
 - proxy: run the normal async proxy
 - benchmark: run and invoke `perf stat` against self (Linux only)
 - rl-inference: placeholder to run the RL-based proxy (not implemented yet)

This script wraps `async_proxy.run_proxy_async` and provides a single CLI for both drone and gcs roles.
"""
import argparse
import asyncio
import subprocess
import os
import sys
import time
from datetime import datetime

# Put repo root on path
ROOT = os.path.dirname(os.path.abspath(__file__))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from async_proxy import run_proxy_async

# Try to import ip_config from both sides; prefer per-role when selecting
try:
    from gcs.ip_config import GCS_HOST, PORT_GCS_LISTEN_ENCRYPTED_TLM, PORT_GCS_LISTEN_PLAINTEXT_CMD, PORT_GCS_FORWARD_DECRYPTED_TLM
except Exception:
    # fallbacks
    GCS_HOST = '127.0.0.1'
    PORT_GCS_LISTEN_ENCRYPTED_TLM = 5821
    PORT_GCS_LISTEN_PLAINTEXT_CMD = 5822
    PORT_GCS_FORWARD_DECRYPTED_TLM = 5823

try:
    from drone.ip_config import DRONE_HOST, PORT_DRONE_LISTEN_ENCRYPTED_CMD, PORT_DRONE_LISTEN_PLAINTEXT_TLM, PORT_DRONE_FORWARD_DECRYPTED_CMD
except Exception:
    DRONE_HOST = '127.0.0.1'
    PORT_DRONE_LISTEN_ENCRYPTED_CMD = 5811
    PORT_DRONE_LISTEN_PLAINTEXT_TLM = 5813
    PORT_DRONE_FORWARD_DECRYPTED_CMD = 5812


def parse_args():
    p = argparse.ArgumentParser(description='Unified CEREBRUS Security Proxy')
    p.add_argument('--role', choices=['gcs', 'drone'], required=False,
                   help='Role of this instance. If omitted, the script will try to auto-detect using values from ip_config.')
    p.add_argument('--algo', required=False, help='algorithm name (e.g., dilithium3, k768, ascon). If omitted, the script will pick a sensible default.')
    p.add_argument('--mode', choices=['proxy', 'benchmark', 'rl-inference'], default='proxy')
    p.add_argument('--duration', type=int, default=30, help='benchmark duration (seconds)')
    p.add_argument('--public-host', default=None, help='Optional override for public bind host (useful for loopback testing)')
    p.add_argument('--local-in-port', type=int, default=None)
    p.add_argument('--local-out-port', type=int, default=None)
    p.add_argument('--gcs-host', default='127.0.0.1')
    return p.parse_args()


async def _run_proxy(role, algo, public_host, public_port, local_in, local_out, gcs_host, benchmark_duration=0):
    # In benchmark mode, launch perf against self (Linux-only)
    perf_proc = None
    perf_log = None
    if benchmark_duration > 0 and sys.platform.startswith('linux'):
        pid = os.getpid()
        perf_log = f'perf_results_{algo}_{int(time.time())}.log'
        perf_cmd = ['perf', 'stat', '-e', 'cycles,instructions,cache-misses,branch-misses', '-p', str(pid), '-o', perf_log]
        try:
            print('[benchmark] launching perf:', ' '.join(perf_cmd))
            perf_proc = subprocess.Popen(perf_cmd)
        except Exception as e:
            print('[benchmark] failed to launch perf:', e)
            perf_proc = None

    # Run the proxy until cancelled or duration expires
    task = asyncio.create_task(run_proxy_async(role, algo, public_host, public_port, '127.0.0.1', local_in, local_out, gcs_host))
    if benchmark_duration > 0:
        try:
            await asyncio.wait_for(task, timeout=benchmark_duration)
        except asyncio.TimeoutError:
            print('[benchmark] duration elapsed; cancelling proxy task')
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
    else:
        await task

    if perf_proc:
        try:
            perf_proc.terminate()
            perf_proc.wait(timeout=5)
            print('[benchmark] perf finished; log=', perf_log)
            # parse perf log and append to master CSV
            try:
                _parse_perf_log(perf_log, algo, benchmark_duration)
            except Exception as e:
                print('[benchmark] error parsing perf log:', e)
            # remove perf log file after parsing
            try:
                os.remove(perf_log)
            except Exception:
                pass
        except Exception as e:
            print('[benchmark] error stopping perf:', e)


def _parse_perf_log(log_file: str, algo_name: str, duration: int):
    """Parse perf stat output file and append results to master_benchmark_results.csv

    Expected metrics:
      - instructions
      - cycles
      - insn per cycle (IPC)
      - cache-misses
      - branch-misses
    """
    import re
    timestamp = datetime.utcnow().isoformat()
    metrics = {
        'instructions': None,
        'cycles': None,
        'ipc': None,
        'cache_misses': None,
        'branch_misses': None,
    }

    with open(log_file, 'r', errors='ignore') as f:
        text = f.read()

    # regex helpers
    # matches lines like:  1,234,567 instructions
    def extract_int(pattern):
        m = re.search(pattern, text, re.IGNORECASE)
        if not m:
            return None
        # remove commas
        val = m.group(1).replace(',', '').strip()
        try:
            return int(val)
        except Exception:
            return None

    # instructions
    metrics['instructions'] = extract_int(r"([0-9,]+)\s+instructions")
    # cycles
    metrics['cycles'] = extract_int(r"([0-9,]+)\s+cycles")
    # cache-misses
    metrics['cache_misses'] = extract_int(r"([0-9,]+)\s+cache-misses")
    # branch-misses
    metrics['branch_misses'] = extract_int(r"([0-9,]+)\s+branch-misses")

    # IPC (insn per cycle) - perf sometimes reports as "insn per cycle: 0.49" or as a line
    m_ipc = re.search(r"insn per cycle\s*[:]?\s*([0-9]+\.?[0-9]*)", text, re.IGNORECASE)
    if m_ipc:
        try:
            metrics['ipc'] = float(m_ipc.group(1))
        except Exception:
            metrics['ipc'] = None
    else:
        # alt pattern: "instructions per cycle" or similar
        m2 = re.search(r"([0-9]+\.[0-9]+)\s+insn per cycle", text, re.IGNORECASE)
        if m2:
            try:
                metrics['ipc'] = float(m2.group(1))
            except Exception:
                metrics['ipc'] = None

    # ensure numeric defaults
    for k in ['instructions', 'cycles', 'cache_misses', 'branch_misses']:
        if metrics[k] is None:
            metrics[k] = 0
    if metrics['ipc'] is None:
        metrics['ipc'] = 0.0

    out_row = [timestamp, algo_name, int(duration), metrics['ipc'], metrics['instructions'], metrics['cycles'], metrics['cache_misses'], metrics['branch_misses']]

    master_file = os.path.join(ROOT, 'master_benchmark_results.csv')
    header = ['timestamp', 'algorithm', 'duration_seconds', 'ipc', 'total_instructions', 'total_cycles', 'total_cache_misses', 'total_branch_misses']
    write_header = not os.path.exists(master_file)
    with open(master_file, 'a', newline='') as mf:
        import csv
        writer = csv.writer(mf)
        if write_header:
            writer.writerow(header)
        writer.writerow(out_row)
    print(f'[benchmark] appended results to {master_file}')


def main():
    import socket

    args = parse_args()

    # Auto-select algorithm if not provided
    if not args.algo:
        # Priority: environment variable DEFAULT_ALGO, then prefer k768 if present, else pick first from drone/ folder
        default_algo = os.environ.get('DEFAULT_ALGO')
        if default_algo:
            args.algo = default_algo
            print(f'[auto-select] using DEFAULT_ALGO from env: {args.algo}')
        else:
            # prefer k768
            candidates = []
            try:
                for fn in os.listdir(os.path.join(ROOT, 'drone')):
                    if fn.startswith('drone_') and fn.endswith('.py'):
                        candidates.append(fn.replace('drone_', '').replace('.py', ''))
            except Exception:
                pass
            if 'k768' in candidates:
                args.algo = 'k768'
            elif candidates:
                args.algo = candidates[0]
            else:
                args.algo = 'k768'  # last-resort fallback
            print(f'[auto-select] selected algorithm: {args.algo}')

    def _resolve_host_ip(hostname):
        try:
            return socket.gethostbyname(hostname)
        except Exception:
            return None

    def _guess_role_from_local(gcs_host, drone_host):
        # Gather likely local IPs
        candidates = set()
        try:
            # primary outbound IP (works even without external connectivity for many setups)
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                s.connect((gcs_host or '8.8.8.8', 80))
                candidates.add(s.getsockname()[0])
            finally:
                s.close()
        except Exception:
            pass
        try:
            candidates.add(socket.gethostbyname(socket.gethostname()))
        except Exception:
            pass
        candidates.add('127.0.0.1')

        # resolve configured hosts
        gcs_ip = _resolve_host_ip(gcs_host) if gcs_host else None
        drone_ip = _resolve_host_ip(drone_host) if drone_host else None

        # Compare
        if gcs_ip and gcs_ip in candidates:
            return 'gcs'
        if drone_ip and drone_ip in candidates:
            return 'drone'

        # Not sure
        return None

    # If role not provided, attempt to infer from ip_config constants
    if not args.role:
        guessed = _guess_role_from_local(GCS_HOST, DRONE_HOST)
        if guessed:
            print(f'[auto-detect] inferred role={guessed} from local host IP')
            args.role = guessed
        else:
            print('[auto-detect] could not determine role from local IPs. Please pass --role gcs|drone or set appropriate ip_config values.')
            # fall back to 'drone' to preserve backward compatibility for scripts that expect a default
            args.role = 'drone'
            print('[auto-detect] defaulting to role=drone')

    if args.role == 'gcs':
        public_host = args.public_host or GCS_HOST
        public_port = PORT_GCS_LISTEN_ENCRYPTED_TLM
        remote_host = DRONE_HOST
        # local ports
        local_in = args.local_in_port or PORT_GCS_LISTEN_PLAINTEXT_CMD
        local_out = args.local_out_port or PORT_GCS_FORWARD_DECRYPTED_TLM
    else:
        public_host = args.public_host or DRONE_HOST
        public_port = PORT_DRONE_LISTEN_ENCRYPTED_CMD
        remote_host = GCS_HOST
        # Correct drone local mapping: local_in is where proxy listens for plaintext from local app
        local_in = args.local_in_port or PORT_DRONE_LISTEN_PLAINTEXT_TLM
        local_out = args.local_out_port or PORT_DRONE_FORWARD_DECRYPTED_CMD

    if args.mode == 'proxy':
        asyncio.run(_run_proxy(args.role, args.algo, public_host, public_port, local_in, local_out, args.gcs_host, 0))
    elif args.mode == 'benchmark':
        asyncio.run(_run_proxy(args.role, args.algo, public_host, public_port, local_in, local_out, args.gcs_host, args.duration))
    else:
        print('rl-inference mode is not implemented yet')


if __name__ == '__main__':
    main()
