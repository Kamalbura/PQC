#!/usr/bin/env python3
"""
Interactive GCS Application
Simulates a real Ground Control Station with MANUAL control for testing PQC proxies

This app:
1. Sends command data to the GCS PQC proxy (port 5810) when user presses ENTER
2. Receives telemetry from the GCS PQC proxy (port 5822) automatically
3. Logs all sent and received data to gcs_app_log.txt

Usage: python interactive_gcs_app.py
Controls: Press ENTER to send command, Ctrl+C to exit
"""

import socket
import threading
import time
import json
import sys
import argparse
from datetime import datetime

# Import GCS-side configuration
try:
    from gcs.ip_config import *
except ImportError:
    # Fallback configuration
    GCS_HOST = "127.0.0.1"
    DRONE_HOST = "127.0.0.1"
    PORT_GCS_LISTEN_PLAINTEXT_CMD = 5810
    PORT_GCS_FORWARD_DECRYPTED_TLM = 5822

LOG_FILE = "gcs_app_log.txt"

class InteractiveGCSApp:
    def __init__(self):
        self.running = False
        self.command_counter = 0
        self.telemetry_counter = 0
        self.send_sock = None
        self.auto_mode = False
        self.auto_rate = 100
        self.auto_duration = None
        
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
    
    def generate_command(self):
        """Generate realistic command data"""
        self.command_counter += 1
        
        # Cycle through different command types
        command_types = [
            {
                "msg_id": "SET_MODE",
                "mode": "AUTO" if self.command_counter % 2 == 0 else "GUIDED",
                "custom_mode": 4
            },
            {
                "msg_id": "MISSION_ITEM", 
                "seq": self.command_counter,
                "frame": 3,
                "command": 16,  # NAV_WAYPOINT
                "param1": 0.0,
                "param2": 0.0,
                "param3": 0.0,
                "param4": 0.0,
                "x": round(40.7128 + (self.command_counter % 10) * 0.001, 6),
                "y": round(-74.0060 + (self.command_counter % 10) * 0.001, 6),
                "z": round(50.0 + (self.command_counter % 5) * 10.0, 1)
            },
            {
                "msg_id": "COMMAND_LONG",
                "command": 400,  # ARM_DISARM
                "param1": 1.0 if (self.command_counter % 4) < 2 else 0.0,
                "param2": 0.0,
                "param3": 0.0,
                "param4": 0.0,
                "param5": 0.0,
                "param6": 0.0,
                "param7": 0.0
            },
            {
                "msg_id": "SET_POSITION_TARGET_GLOBAL_INT",
                "coordinate_frame": 6,
                "type_mask": 0b0000111111111000,
                "lat_int": int((40.7128 + (self.command_counter % 10) * 0.001) * 1e7),
                "lon_int": int((-74.0060 + (self.command_counter % 10) * 0.001) * 1e7),
                "alt": round(100.0 + (self.command_counter % 10) * 5.0, 1)
            },
            {
                "msg_id": "REQUEST_DATA_STREAM",
                "req_stream_id": 1,
                "req_message_rate": 5,
                "start_stop": 1
            }
        ]
        
        base_command = command_types[self.command_counter % len(command_types)]
        command = {
            "counter": self.command_counter,
            "timestamp": datetime.now().isoformat(),
            "system_id": 255,  # GCS system ID
            "component_id": 190,  # GCS component ID
            "target_system": 1,
            "target_component": 1,
            **base_command
        }
        
        return json.dumps(command, indent=2).encode('utf-8')
    
    def send_command_now(self):
        """Send one command message immediately"""
        if not self.send_sock:
            return False
            
        try:
            command_data = self.generate_command()
            self.send_sock.sendto(command_data, (GCS_HOST, PORT_GCS_LISTEN_PLAINTEXT_CMD))
            
            self.log_message("SENT_COMMAND", command_data.decode('utf-8'), PORT_GCS_LISTEN_PLAINTEXT_CMD)
            
            # Extract command type for display
            try:
                cmd_obj = json.loads(command_data.decode('utf-8'))
                cmd_type = cmd_obj.get('msg_id', 'UNKNOWN')
                print(f"✅ Sent command #{self.command_counter}: {cmd_type}")
            except:
                print(f"✅ Sent command #{self.command_counter}")
                
            return True
        except Exception as e:
            self.log_message("ERROR", f"Failed to send command: {e}")
            print(f"❌ Error sending command: {e}")
            return False

    def _auto_sender_thread(self):
        """Continuously send commands at self.auto_rate packets/sec for optional duration."""
        interval = 1.0 / float(self.auto_rate)
        start_time = time.time()

        while self.running:
            now = time.time()
            if self.auto_duration is not None and (now - start_time) >= self.auto_duration:
                break

            success = self.send_command_now()
            # maintain rate
            time.sleep(interval)

        self.log_message("AUTO", f"Auto sender stopped after {time.time() - start_time:.2f}s")

    def _auto_stats_thread(self):
        """Log per-second stats while auto sender is running."""
        last_total = self.command_counter
        while self.running:
            time.sleep(1)
            current_total = self.command_counter
            delta = current_total - last_total
            last_total = current_total
            self.log_message("AUTO_STATS", f"Commands sent in last second: {delta}")
    
    def telemetry_receiver_thread(self):
        """Receive telemetry from GCS PQC proxy"""
        self.log_message("STARTUP", f"Telemetry receiver starting - listening on {GCS_HOST}:{PORT_GCS_FORWARD_DECRYPTED_TLM}")
        
        # Create UDP socket for receiving telemetry
        recv_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        recv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            recv_sock.bind((GCS_HOST, PORT_GCS_FORWARD_DECRYPTED_TLM))
            recv_sock.settimeout(1.0)  # 1 second timeout for graceful shutdown
            
            while self.running:
                try:
                    # Receive telemetry data
                    data, addr = recv_sock.recvfrom(65535)
                    self.telemetry_counter += 1
                    
                    self.log_message("RECEIVED_TELEMETRY", data.decode('utf-8'), PORT_GCS_FORWARD_DECRYPTED_TLM)
                    
                    # Simulate telemetry processing and display
                    try:
                        telemetry = json.loads(data.decode('utf-8'))
                        alt = telemetry.get('altitude', '?')
                        speed = telemetry.get('ground_speed', '?')
                        batt = telemetry.get('battery_voltage', '?')
                        mode = telemetry.get('flight_mode', '?')
                        armed = telemetry.get('armed', '?')
                        
                        flight_info = f"Alt:{alt}m Speed:{speed}m/s Batt:{batt}V Mode:{mode} Armed:{armed}"
                        self.log_message("PROCESSED_TELEMETRY", flight_info)
                        print(f"📡 Telemetry #{self.telemetry_counter}: {flight_info}")
                    except json.JSONDecodeError:
                        self.log_message("PROCESSED_TELEMETRY", f"Processing raw telemetry: {data.decode('utf-8')[:50]}...")
                        print(f"📡 Received raw telemetry #{self.telemetry_counter}")
                    
                except socket.timeout:
                    continue  # Normal timeout, check if still running
                except Exception as e:
                    if self.running:  # Only log if we're supposed to be running
                        self.log_message("ERROR", f"Telemetry receiver error: {e}")
                    
        except Exception as e:
            self.log_message("ERROR", f"Telemetry receiver startup error: {e}")
        finally:
            recv_sock.close()
            self.log_message("SHUTDOWN", "Telemetry receiver stopped")
    
    def interactive_control_loop(self):
        """Handle user input for sending commands"""
        print("\n🎮 INTERACTIVE GCS CONTROL")
        print("=" * 40)
        print("Press ENTER to send command")
        print("Type 'status' to see current stats")
        print("Type 'quit' or Ctrl+C to exit")
        print("=" * 40)
        
        while self.running:
            try:
                user_input = input(f"\n[GCS Ready - Sent: {self.command_counter}, Received: {self.telemetry_counter}] >>> ").strip().lower()
                
                if user_input in ['quit', 'exit', 'q']:
                    print("Exiting...")
                    break
                elif user_input == 'status':
                    print(f"📊 Status: Commands sent: {self.command_counter}, Telemetry received: {self.telemetry_counter}")
                elif user_input == '' or user_input == 'send':
                    # Send command on Enter
                    self.send_command_now()
                else:
                    print("Commands: [ENTER]=send command, 'status'=show stats, 'quit'=exit")
                    
            except (KeyboardInterrupt, EOFError):
                print("\nReceived interrupt signal, stopping...")
                break
    
    def start(self):
        """Start the interactive GCS application"""
        self.running = True
        
        # Clear log file and write header
        with open(LOG_FILE, "w", encoding="utf-8") as f:
            f.write(f"=== Interactive GCS Application Log Started at {datetime.now()} ===\n")
            f.write(f"Configuration: GCS_HOST={GCS_HOST}, DRONE_HOST={DRONE_HOST}\n")
            f.write(f"Command Output Port: {PORT_GCS_LISTEN_PLAINTEXT_CMD}\n")
            f.write(f"Telemetry Input Port: {PORT_GCS_FORWARD_DECRYPTED_TLM}\n")
            f.write("=" * 80 + "\n")
        
        self.log_message("STARTUP", "Interactive GCS Application starting...")
        
        # Create UDP socket for sending commands
        self.send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        
        # Start telemetry receiver thread
        telemetry_thread = threading.Thread(target=self.telemetry_receiver_thread, daemon=True)
        telemetry_thread.start()

        # If auto mode is enabled, start the auto sender and stats thread
        if self.auto_mode:
            sender_thread = threading.Thread(target=self._auto_sender_thread, daemon=True)
            stats_thread = threading.Thread(target=self._auto_stats_thread, daemon=True)
            sender_thread.start()
            stats_thread.start()
        
        self.log_message("STARTUP", "Telemetry receiver started, waiting for user input...")
        
        try:
            # Start interactive control loop
            self.interactive_control_loop()
        except Exception as e:
            self.log_message("ERROR", f"Interactive control error: {e}")
        finally:
            self.stop()
    
    def stop(self):
        """Stop the interactive GCS application"""
        self.log_message("SHUTDOWN", "Stopping Interactive GCS Application...")
        self.running = False
        
        if self.send_sock:
            self.send_sock.close()
            
        time.sleep(1)  # Give threads time to cleanup

def main():
    print("=== Interactive GCS Application ===")
    print(f"Command Output: {GCS_HOST}:{PORT_GCS_LISTEN_PLAINTEXT_CMD}")
    print(f"Telemetry Input: {GCS_HOST}:{PORT_GCS_FORWARD_DECRYPTED_TLM}")
    print(f"Log File: {LOG_FILE}")
    print("\nThis app gives you MANUAL control over command sending.")
    parser = argparse.ArgumentParser(description="Interactive GCS App")
    parser.add_argument('--auto', action='store_true', help='Run in automatic send mode')
    parser.add_argument('--rate', type=int, default=100, help='Packets per second when in auto mode (default: 100)')
    parser.add_argument('--duration', type=int, default=None, help='Duration in seconds for auto mode (optional)')
    args = parser.parse_args()

    app = InteractiveGCSApp()
    if args.auto:
        app.auto_mode = True
        app.auto_rate = max(1, args.rate)
        app.auto_duration = args.duration

    app.start()

if __name__ == "__main__":
    main()