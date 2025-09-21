#!/usr/bin/env python3
"""
Interactive Drone Application
Simulates a real drone flight controller with MANUAL control for testing PQC proxies

This app:
1. Sends telemetry data to the drone PQC proxy (port 5820) when user presses ENTER
2. Receives commands from the drone PQC proxy (port 5812) automatically
3. Logs all sent and received data to drone_app_log.txt

Usage: python interactive_drone_app.py
Controls: Press ENTER to send telemetry, Ctrl+C to exit
"""

import socket
import threading
import time
import json
import sys
import argparse
from datetime import datetime

# Import drone-side configuration
try:
    from drone.ip_config import *
except ImportError:
    # Fallback configuration
    DRONE_HOST = "127.0.0.1"
    PORT_DRONE_LISTEN_PLAINTEXT_TLM = 5820
    PORT_DRONE_FORWARD_DECRYPTED_CMD = 5812

LOG_FILE = "drone_app_log.txt"

class InteractiveDroneApp:
    def __init__(self):
        self.running = False
        self.telemetry_counter = 0
        self.command_counter = 0
        self.send_sock = None
        self.auto_mode = False
        self.auto_rate = 100  # packets per second by default
        self.auto_duration = None  # seconds
        
    def log_message(self, message_type, data, port=None):
        """Log messages with timestamp"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        log_entry = f"[{timestamp}] {message_type}"
        if port:
            log_entry += f" (port {port})"
        log_entry += f": {data}\n"
        
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(log_entry)
        print(log_entry.strip())
    
    def generate_telemetry(self):
        """Generate realistic telemetry data"""
        self.telemetry_counter += 1
        telemetry = {
            "msg_id": "HEARTBEAT",
            "counter": self.telemetry_counter,
            "timestamp": datetime.now().isoformat(),
            "system_id": 1,
            "component_id": 1,
            "battery_voltage": round(12.4 + (self.telemetry_counter % 10) * 0.1, 2),
            "gps_lat": round(40.7128 + (self.telemetry_counter % 100) * 0.0001, 6),
            "gps_lon": round(-74.0060 + (self.telemetry_counter % 100) * 0.0001, 6),
            "altitude": round(100.0 + (self.telemetry_counter % 50) * 2.0, 1),
            "ground_speed": round(15.5 + (self.telemetry_counter % 10) * 0.5, 1),
            "heading": (self.telemetry_counter * 10) % 360,
            "flight_mode": "GUIDED",
            "armed": True,
            "satellites": min(12, 4 + (self.telemetry_counter % 9))
        }
        return json.dumps(telemetry, indent=2).encode('utf-8')
    
    def send_telemetry_now(self):
        """Send one telemetry message immediately"""
        if not self.send_sock:
            return False
            
        try:
            telemetry_data = self.generate_telemetry()
            self.send_sock.sendto(telemetry_data, (DRONE_HOST, PORT_DRONE_LISTEN_PLAINTEXT_TLM))
            
            self.log_message("SENT_TELEMETRY", telemetry_data.decode('utf-8'), PORT_DRONE_LISTEN_PLAINTEXT_TLM)
            print(f"✅ Sent telemetry #{self.telemetry_counter} to proxy")
            return True
        except Exception as e:
            self.log_message("ERROR", f"Failed to send telemetry: {e}")
            print(f"❌ Error sending telemetry: {e}")
            return False

    def _auto_sender_thread(self):
        """Continuously send telemetry at self.auto_rate packets/sec for optional duration."""
        interval = 1.0 / float(self.auto_rate)
        start_time = time.time()
        sent_in_second = 0
        last_second = int(start_time)

        while self.running:
            now = time.time()
            if self.auto_duration is not None and (now - start_time) >= self.auto_duration:
                break

            # send one packet
            success = self.send_telemetry_now()
            sent_in_second += 1 if success else 0

            # Sleep to maintain rate
            time.sleep(interval)

        self.log_message("AUTO", f"Auto sender stopped after {time.time() - start_time:.2f}s")

    def _auto_stats_thread(self):
        """Log per-second stats while auto sender is running."""
        last_total = self.telemetry_counter
        while self.running:
            time.sleep(1)
            current_total = self.telemetry_counter
            delta = current_total - last_total
            last_total = current_total
            self.log_message("AUTO_STATS", f"Packets sent in last second: {delta}")
    
    def command_receiver_thread(self):
        """Receive commands from drone PQC proxy"""
        self.log_message("STARTUP", f"Command receiver starting - listening on {DRONE_HOST}:{PORT_DRONE_FORWARD_DECRYPTED_CMD}")
        
        # Create UDP socket for receiving commands
        recv_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        recv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            recv_sock.bind((DRONE_HOST, PORT_DRONE_FORWARD_DECRYPTED_CMD))
            recv_sock.settimeout(1.0)  # 1 second timeout for graceful shutdown
            
            while self.running:
                try:
                    # Receive command data
                    data, addr = recv_sock.recvfrom(65535)
                    self.command_counter += 1
                    
                    self.log_message("RECEIVED_COMMAND", data.decode('utf-8'), PORT_DRONE_FORWARD_DECRYPTED_CMD)
                    
                    # Simulate command processing
                    try:
                        command = json.loads(data.decode('utf-8'))
                        cmd_type = command.get('msg_id', 'UNKNOWN')
                        target_sys = command.get('target_system', '?')
                        self.log_message("PROCESSED_COMMAND", f"Processing {cmd_type} from system {target_sys}")
                        print(f"📨 Received command #{self.command_counter}: {cmd_type}")
                    except json.JSONDecodeError:
                        self.log_message("PROCESSED_COMMAND", f"Processing raw command: {data.decode('utf-8')[:50]}...")
                        print(f"📨 Received raw command #{self.command_counter}")
                    
                except socket.timeout:
                    continue  # Normal timeout, check if still running
                except Exception as e:
                    if self.running:  # Only log if we're supposed to be running
                        self.log_message("ERROR", f"Command receiver error: {e}")
                    
        except Exception as e:
            self.log_message("ERROR", f"Command receiver startup error: {e}")
        finally:
            recv_sock.close()
            self.log_message("SHUTDOWN", "Command receiver stopped")
    
    def interactive_control_loop(self):
        """Handle user input for sending telemetry"""
        print("\n🎮 INTERACTIVE DRONE CONTROL")
        print("=" * 40)
        print("Press ENTER to send telemetry")
        print("Type 'status' to see current stats")
        print("Type 'quit' or Ctrl+C to exit")
        print("=" * 40)
        
        while self.running:
            try:
                user_input = input(f"\n[Drone Ready - Sent: {self.telemetry_counter}, Received: {self.command_counter}] >>> ").strip().lower()
                
                if user_input in ['quit', 'exit', 'q']:
                    print("Exiting...")
                    break
                elif user_input == 'status':
                    print(f"📊 Status: Telemetry sent: {self.telemetry_counter}, Commands received: {self.command_counter}")
                elif user_input == '' or user_input == 'send':
                    # Send telemetry on Enter
                    self.send_telemetry_now()
                else:
                    print("Commands: [ENTER]=send telemetry, 'status'=show stats, 'quit'=exit")
                    
            except (KeyboardInterrupt, EOFError):
                print("\nReceived interrupt signal, stopping...")
                break
    
    def start(self):
        """Start the interactive drone application"""
        self.running = True
        
        # Clear log file and write header
        with open(LOG_FILE, "w", encoding="utf-8") as f:
            f.write(f"=== Interactive Drone Application Log Started at {datetime.now()} ===\n")
            f.write(f"Configuration: DRONE_HOST={DRONE_HOST}\n")
            f.write(f"Telemetry Output Port: {PORT_DRONE_LISTEN_PLAINTEXT_TLM}\n")
            f.write(f"Command Input Port: {PORT_DRONE_FORWARD_DECRYPTED_CMD}\n")
            f.write("=" * 80 + "\n")
        
        self.log_message("STARTUP", "Interactive Drone Application starting...")

        # Create UDP socket for sending telemetry
        self.send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        # Start command receiver thread
        command_thread = threading.Thread(target=self.command_receiver_thread, daemon=True)
        command_thread.start()

        # If auto mode is enabled, start the auto sender and stats thread
        if self.auto_mode:
            sender_thread = threading.Thread(target=self._auto_sender_thread, daemon=True)
            stats_thread = threading.Thread(target=self._auto_stats_thread, daemon=True)
            sender_thread.start()
            stats_thread.start()

        self.log_message("STARTUP", "Command receiver started, waiting for user input...")
        
        try:
            # Start interactive control loop
            self.interactive_control_loop()
        except Exception as e:
            self.log_message("ERROR", f"Interactive control error: {e}")
        finally:
            self.stop()
    
    def stop(self):
        """Stop the interactive drone application"""
        self.log_message("SHUTDOWN", "Stopping Interactive Drone Application...")
        self.running = False
        
        if self.send_sock:
            self.send_sock.close()
            
        time.sleep(1)  # Give threads time to cleanup

def main():
    print("=== Interactive Drone Application ===")
    print(f"Telemetry Output: {DRONE_HOST}:{PORT_DRONE_LISTEN_PLAINTEXT_TLM}")
    print(f"Command Input: {DRONE_HOST}:{PORT_DRONE_FORWARD_DECRYPTED_CMD}")
    print(f"Log File: {LOG_FILE}")
    print("\nThis app gives you MANUAL control over telemetry sending.")
    parser = argparse.ArgumentParser(description="Interactive Drone App")
    parser.add_argument('--auto', action='store_true', help='Run in automatic send mode')
    parser.add_argument('--rate', type=int, default=100, help='Packets per second when in auto mode (default: 100)')
    parser.add_argument('--duration', type=int, default=None, help='Duration in seconds for auto mode (optional)')
    args = parser.parse_args()

    app = InteractiveDroneApp()
    if args.auto:
        app.auto_mode = True
        app.auto_rate = max(1, args.rate)
        app.auto_duration = args.duration

    app.start()

if __name__ == "__main__":
    main()