# Async single-port proxy (async_proxy.py)

This project now includes an asyncio-based single-port proxy designed to work well with MAVProxy.

Quick start (local single-machine test):

- Start the GCS proxy:

```powershell
# From repo root
C:\Users\burak\miniconda3\envs\gcs-env\python.exe c:\Users\burak\Desktop\crypto\sgcs\async_gcs.py
```

- Start the Drone proxy:

```powershell
C:\Users\burak\miniconda3\envs\gcs-env\python.exe c:\Users\burak\Desktop\crypto\sdrone\async_drone.py
```

MAVProxy example configuration (GCS side)

```powershell
mavproxy.py --master=tcp:pixhawk:5760 --out=udp:192.168.0.104:5821 --out=udp:127.0.0.1:14550
```

Notes

- The async proxy uses a single public UDP port for GCS/Drone traffic and two local ports (local-in/local-out) to avoid port-binding conflicts with MAVProxy or flight controller clients.
- Crypto operations are offloaded to a thread pool (via asyncio.run_in_executor) so expensive signature operations don't block network I/O.
- `singleport_common.py` still contains the handshake logic and AES key derivation. The async proxy re-uses that code.

Feedback

If you'd like, I can update all `sdrone/` and `sgcs/` wrapper scripts to call the async runners instead of the old synchronous proxies.