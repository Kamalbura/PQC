"""sdrone/ip_config.py

Copy of drone/ip_config.py for single-port drone proxies (sdrone/).
Edit these values when deploying sdrone proxies separately.
"""
from typing import Optional, List
import re, time

# --- HOST ADDRESSES ---
GCS_HOST = "192.168.0.104"
DRONE_HOST = "192.168.0.102"

# --- DRONE ID ---
DRONE_ID = "drone1"

# --- NETWORK PORTS ---
PORT_KEY_EXCHANGE = 5800

# Ports for MAVLink Command Flow (GCS App -> Drone)
PORT_GCS_LISTEN_PLAINTEXT_CMD = 5810
PORT_DRONE_LISTEN_ENCRYPTED_CMD = 5811
PORT_DRONE_FORWARD_DECRYPTED_CMD = 5812

# Ports for MAVLink Telemetry Flow (Drone -> GCS App)
PORT_DRONE_LISTEN_PLAINTEXT_TLM = 5820
PORT_GCS_LISTEN_ENCRYPTED_TLM = 5821
PORT_GCS_FORWARD_DECRYPTED_TLM = 5822

# --- CRYPTOGRAPHY CONSTANTS ---
NONCE_IV_SIZE = 12

def set_hosts_runtime(new_gcs: Optional[str]=None, new_drone: Optional[str]=None) -> List[str]:
    changed=[]
    global GCS_HOST, DRONE_HOST
    if new_gcs and new_gcs != GCS_HOST:
        GCS_HOST = new_gcs; changed.append(f"GCS_HOST->{new_gcs}")
    if new_drone and new_drone != DRONE_HOST:
        DRONE_HOST = new_drone; changed.append(f"DRONE_HOST->{new_drone}")
    return changed

def update_hosts_persistent(new_gcs: Optional[str]=None, new_drone: Optional[str]=None) -> List[str]:
    path = __file__
    try:
        with open(path, 'r', encoding='utf-8') as f:
            content = f.read()
        changes=[]
        def repl_line(src:str, key:str, val:Optional[str]) -> str:
            nonlocal changes
            if not val: return src
            pattern = rf"^(\s*{key}\s*=\s*)\"[^\"]*\""
            ts = time.strftime('%Y-%m-%d %H:%M:%S')
            new_src, n = re.subn(pattern, rf"# updated {ts} \g<0>\n{key} = \"{val}\"", src, count=1, flags=re.MULTILINE)
            if n:
                changes.append(f"{key}->{val}")
                return new_src
            return src
        content2 = repl_line(content, 'GCS_HOST', new_gcs)
        content3 = repl_line(content2, 'DRONE_HOST', new_drone)
        if content3 != content:
            with open(path, 'w', encoding='utf-8') as f:
                f.write(content3)
        return changes
    except Exception:
        return []
