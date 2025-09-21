#!/usr/bin/env python3
"""
mavproxy_serial_bridge.py

Bridge between Pixhawk serial (MAVLink) and local UDP ports so a Pixhawk
connected to the Pi via USB can receive commands from the GCS (via the
proxy chain) and forward telemetry back to the drone-side proxy.

Run on the Pi (drone side):
  python mavproxy_serial_bridge.py --serial-port /dev/ttyUSB0 --baud 57600

Requirements: pyserial (pip install pyserial)
"""

import argparse
import socket
import threading
import time
import sys

def load_drone_config():
    try:
        from drone.ip_config import *
    except Exception as e:
        print(f"Failed to import drone.ip_config: {e}")
        raise
    # collect values into a dict
    return {
        'DRONE_HOST': globals().get('DRONE_HOST'),
        'GCS_HOST': globals().get('GCS_HOST'),
        'PORT_DRONE_LISTEN_PLAINTEXT_TLM': globals().get('PORT_DRONE_LISTEN_PLAINTEXT_TLM'),
        'PORT_DRONE_FORWARD_DECRYPTED_CMD': globals().get('PORT_DRONE_FORWARD_DECRYPTED_CMD'),
    }

def udp_command_listener(listen_host, listen_port, serial_write_fn, stop_event):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((listen_host, listen_port))
    print(f"[BRIDGE] UDP->SERIAL listener bound to {listen_host}:{listen_port}")
    try:
        while not stop_event.is_set():
            try:
                data, addr = sock.recvfrom(65535)
                if not data:
                    continue
                # Write raw bytes to serial (Pixhawk expects MAVLink frames)
                serial_write_fn(data)
            except socket.timeout:
                continue
            except Exception as e:
                print(f"[BRIDGE] UDP listener error: {e}")
                time.sleep(0.1)
    finally:
        sock.close()

def serial_reader_thread(serial_open_fn, udp_target_host, udp_target_port, stop_event):
    # The serial_open_fn is expected to return an object with read(size) and read_until behaviors
    ser = None
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        ser = serial_open_fn()
    except Exception as e:
        print(f"[BRIDGE] Failed to open serial port: {e}")
        return

    print(f"[BRIDGE] Serial->UDP reader started, forwarding to {udp_target_host}:{udp_target_port}")
    try:
        while not stop_event.is_set():
            try:
                data = ser.read(ser.in_waiting or 1)
                if data:
                    sock.sendto(data, (udp_target_host, udp_target_port))
                else:
                    time.sleep(0.001)
            except Exception as e:
                print(f"[BRIDGE] Serial read error: {e}")
                time.sleep(0.1)
    finally:
        try:
            ser.close()
        except Exception:
            pass
        sock.close()

def main():
    p = argparse.ArgumentParser(description='Pixhawk Serial <-> UDP bridge for Drone side')
    p.add_argument('--serial-port', required=False, help='Serial device (e.g. /dev/ttyUSB0). If omitted, autoguess /dev/serial/by-id or /dev/ttyUSB0')
    p.add_argument('--baud', type=int, default=57600, help='Serial baudrate (default 57600)')
    p.add_argument('--bind-host', help='Host to bind UDP listener to (default: DRONE_HOST)')
    p.add_argument('--side', choices=['drone'], default='drone', help='This bridge is intended for the drone side (pixhawk on Pi)')
    args = p.parse_args()

    cfg = load_drone_config()

    bind_host = args.bind_host or cfg['DRONE_HOST'] or '0.0.0.0'

    udp_cmd_listen_port = cfg['PORT_DRONE_FORWARD_DECRYPTED_CMD']
    udp_tlm_dest_port = cfg['PORT_DRONE_LISTEN_PLAINTEXT_TLM']
    udp_tlm_dest_host = cfg['DRONE_HOST']

    # Serial port auto-guess
    serial_port = args.serial_port
    if not serial_port:
        # try common Pi device names
        candidate = '/dev/serial/by-id'
        import os
        if os.path.isdir(candidate):
            # pick first entry
            try:
                entries = os.listdir(candidate)
                if entries:
                    serial_port = os.path.join(candidate, entries[0])
            except Exception:
                pass
        if not serial_port:
            serial_port = '/dev/ttyUSB0'

    baud = args.baud

    stop_event = threading.Event()

    # Serial open function deferred to runtime so import of pyserial is optional at compile-time
    def open_serial():
        try:
            import serial
        except Exception as e:
            raise RuntimeError(f"pyserial required: {e}")
        ser = serial.Serial(serial_port, baudrate=baud, timeout=0)
        return ser

    # writer wrapper
    ser_lock = threading.Lock()
    ser_obj = {'instance': None}

    def serial_write(data: bytes):
        try:
            if ser_obj['instance'] is None:
                ser_obj['instance'] = open_serial()
            with ser_lock:
                ser_obj['instance'].write(data)
        except Exception as e:
            print(f"[BRIDGE] Serial write error: {e}")

    def serial_open_fn():
        if ser_obj['instance'] is None:
            ser_obj['instance'] = open_serial()
        return ser_obj['instance']

    # Start threads
    t_udp = threading.Thread(target=udp_command_listener, args=(bind_host, udp_cmd_listen_port, serial_write, stop_event), daemon=True)
    t_serial = threading.Thread(target=serial_reader_thread, args=(serial_open_fn, udp_tlm_dest_host, udp_tlm_dest_port, stop_event), daemon=True)

    t_udp.start()
    t_serial.start()

    print("READY")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("Shutting down...")
        stop_event.set()
        time.sleep(0.5)

if __name__ == '__main__':
    main()
