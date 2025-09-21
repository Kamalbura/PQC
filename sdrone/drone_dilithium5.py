from singleport_common import run_proxy
from sdrone.ip_config import DRONE_HOST, GCS_HOST, PORT_DRONE_LISTEN_ENCRYPTED_CMD, PORT_DRONE_FORWARD_DECRYPTED_CMD

if __name__ == '__main__':
    run_proxy('drone', 'dilithium5', public_host=DRONE_HOST, public_port=PORT_DRONE_LISTEN_ENCRYPTED_CMD,
              local_bind='127.0.0.1', local_port=PORT_DRONE_FORWARD_DECRYPTED_CMD, gcs_host=GCS_HOST)
