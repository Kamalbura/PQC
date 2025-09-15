# ==============================================================================
# ip_config.py (GCS Version)
#
# PURPOSE:
#   Centralized IP and Port Configuration for the GCS and Drone framework.
#   This configuration matches the research paper implementation exactly:
#   - Port Range: 5800-5822 (standardized across GCS/Drone)
#   - Algorithm mapping: c1-c8 as specified in paper
#   - UDP proxy pattern for fair power comparison
#
# RESEARCH PAPER COMPLIANCE:
#   ✅ All hosts set for network deployment
#   ✅ Port architecture: 5800-5822 as documented
#   ✅ Supports 8 algorithms (c1-c8) with uniform testing
# ==============================================================================

# --- HOST ADDRESSES ---
# Updated 2023-09-13 GCS_HOST = "192.168.0.104"
GCS_HOST = "127.0.0.1"    # Localhost for single-machine testing
# Updated 2023-09-13 DRONE_HOST = "192.168.0.101" 
DRONE_HOST = "127.0.0.1"  # Localhost for single-machine testing

# --- DRONE ID ---
DRONE_ID = "drone1"

# --- NETWORK PORTS (Research Paper Specification) ---
# Port Range: 5800-5822 (standardized for algorithm comparison)

# Port for PQC Key Exchange (algorithms c5-c8)
PORT_KEY_EXCHANGE = 5800

# Ports for MAVLink Command Flow (GCS App -> Drone)
PORT_GCS_LISTEN_PLAINTEXT_CMD = 5810    # GCS app sends here
PORT_DRONE_LISTEN_ENCRYPTED_CMD = 5811  # Drone proxy receives  
PORT_DRONE_FORWARD_DECRYPTED_CMD = 5812 # To flight controller

# Ports for MAVLink Telemetry Flow (Drone -> GCS App)
PORT_DRONE_LISTEN_PLAINTEXT_TLM = 5820  # From flight controller
PORT_GCS_LISTEN_ENCRYPTED_TLM = 5821    # GCS proxy receives
PORT_GCS_FORWARD_DECRYPTED_TLM = 5822   # To GCS app

# --- CRYPTOGRAPHY CONSTANTS ---
NONCE_IV_SIZE = 12

# --- ALGORITHM MAPPING (Research Paper c1-c8) ---
ALGORITHM_MAP = {
    "c1": "ascon",      # ASCON-128 AEAD (NIST SP 800-232)
    "c2": "speck",      # SPECK-128/128 (NSA lightweight)
    "c3": "camellia",   # Camellia-128 (ISO standard)
    "c4": "hight",      # HIGHT (Korean standard)
    "c5": "dilithium",  # Dilithium (NIST FIPS 204)
    "c6": "kyber",      # Kyber (NIST FIPS 203)
    "c7": "sphincs",    # SPHINCS+ (NIST Round 3)
    "c8": "falcon"      # Falcon (NIST Round 3)
}

# --- RUNTIME/PERSISTENT UPDATE HELPERS (for Scheduler UI) ---
# Runtime updates affect this module in-memory only (callers already imported it).
# Persistent updates modify this file on disk by replacing the lines for GCS_HOST/DRONE_HOST.
from typing import Optional, List
import re, time

def set_hosts_runtime(new_gcs: Optional[str]=None, new_drone: Optional[str]=None) -> List[str]:
	changed=[]
	global GCS_HOST, DRONE_HOST
	if new_gcs and new_gcs != GCS_HOST:
		GCS_HOST = new_gcs; changed.append(f"GCS_HOST->{new_gcs}")
	if new_drone and new_drone != DRONE_HOST:
		DRONE_HOST = new_drone; changed.append(f"DRONE_HOST->{new_drone}")
	return changed

def update_hosts_persistent(new_gcs: Optional[str]=None, new_drone: Optional[str]=None) -> List[str]:
	"""Edit this ip_config.py to persist new host values. Returns list of changes applied."""
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