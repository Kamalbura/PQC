#!/usr/bin/env python3
from async_proxy import run_proxy_async
from sgcs import ip_config
import asyncio

def main():
    public_port = ip_config.PORT_GCS_LISTEN_ENCRYPTED_TLM
    local_in = ip_config.PORT_GCS_FORWARD_DECRYPTED_TLM
    local_out = ip_config.PORT_GCS_FORWARD_DECRYPTED_TLM + 1 if hasattr(ip_config, 'PORT_GCS_FORWARD_DECRYPTED_TLM') else 5823
    asyncio.run(run_proxy_async('gcs', 'k768', '0.0.0.0', public_port, '127.0.0.1', local_in, local_out, ip_config.DRONE_HOST))

if __name__ == '__main__':
    main()
