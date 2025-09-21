from singleport_common import run_proxy
from sgcs.ip_config import GCS_HOST, DRONE_HOST, PORT_GCS_LISTEN_ENCRYPTED_TLM, PORT_GCS_FORWARD_DECRYPTED_TLM

if __name__ == '__main__':
    run_proxy('gcs', 'k512', public_host=GCS_HOST, public_port=PORT_GCS_LISTEN_ENCRYPTED_TLM,
              local_bind='127.0.0.1', local_port=PORT_GCS_FORWARD_DECRYPTED_TLM, gcs_host=DRONE_HOST)
