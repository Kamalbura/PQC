#!/usr/bin/env python3
from async_proxy import run_proxy_async
from sdrone import ip_config
import asyncio

def main():
    public_port = ip_config.PORT_DRONE_LISTEN_ENCRYPTED_CMD
    # local_in listens for plaintext from local flight controller
    local_in = ip_config.PORT_DRONE_FORWARD_DECRYPTED_CMD + 1 if hasattr(ip_config, 'PORT_DRONE_FORWARD_DECRYPTED_CMD') else 14551
    # local_out is where the proxy forwards decrypted packets to (flight controller)
    local_out = ip_config.PORT_DRONE_FORWARD_DECRYPTED_CMD
    asyncio.run(run_proxy_async('drone', 'k768', '0.0.0.0', public_port, '127.0.0.1', local_in, local_out, ip_config.GCS_HOST))

if __name__ == '__main__':
    main()
