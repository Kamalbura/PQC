"""
Centralized project-wide IP / port configuration.

Place values here to have a single, authoritative configuration for both
GCS and Drone machines. Individual `gcs/ip_config.py` and `drone/ip_config.py`
will be left intact for standalone deployment, but `run_proxy.py` prefers
this file when it exists.

Edit this file on the host you control and keep values synchronized across
machines when deploying.
"""

# Hosts
GCS_HOST = "192.168.0.104"
DRONE_HOST = "192.168.0.102"

# Ports (research paper defaults)
PORT_KEY_EXCHANGE = 5800

# GCS plaintext command port (where the GCS app would send commands)
PORT_GCS_LISTEN_PLAINTEXT_CMD = 5810
# Drone encrypted command listen port (public)
PORT_DRONE_LISTEN_ENCRYPTED_CMD = 5811
# Drone forward decrypted commands to flight controller
PORT_DRONE_FORWARD_DECRYPTED_CMD = 5812

# Drone plaintext telemetry from FC
PORT_DRONE_LISTEN_PLAINTEXT_TLM = 5820
# GCS encrypted telemetry receive
PORT_GCS_LISTEN_ENCRYPTED_TLM = 5821
# GCS forward decrypted telemetry to GCS app
PORT_GCS_FORWARD_DECRYPTED_TLM = 5822

# Crypto constants
NONCE_IV_SIZE = 12

"""
Utility helpers (optional):
 - You can import this module from scripts and tools to get canonical hosts/ports.
"""
