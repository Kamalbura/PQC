from singleport_common import run_proxy
from sdrone.ip_config import DRONE_HOST, GCS_HOST, PORT_DRONE_LISTEN_ENCRYPTED_CMD, PORT_DRONE_FORWARD_DECRYPTED_CMD

if __name__ == '__main__':
    from sdrone.async_drone import main
    main()
