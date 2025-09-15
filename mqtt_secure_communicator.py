#!/usr/bin/env python3
"""
MQTT Communication Layer for Drone-GCS PQC Algorithm Switching

This module implements secure MQTT communication with mTLS for:
- Real-time algorithm switching based on GCS commands
- DDoS detection heartbeat monitoring
- Secure command/telemetry routing
- Priority-based message handling

Features:
- Topic-based algorithm selection: crypto/algorithm
- Heartbeat monitoring: crypto/heartbeat  
- DDoS alert propagation: crypto/ddos_alert
- QoS levels for reliability during attacks
- Connection resilience and automatic reconnection

Usage: 
  - GCS sends algorithm switch command to crypto/algorithm topic
  - Drone responds by switching PQC proxy dynamically
  - Continuous heartbeat monitoring for DDoS detection
"""

import paho.mqtt.client as mqtt
import ssl
import json
import time
import threading
import subprocess
import os
import signal
from datetime import datetime, timedelta
from enum import Enum

class MQTTTopics:
    """MQTT topic definitions for secure drone-GCS communication"""
    ALGORITHM_SWITCH = "crypto/algorithm"
    HEARTBEAT = "crypto/heartbeat"  
    DDOS_ALERT = "crypto/ddos_alert"
    SYSTEM_STATUS = "crypto/status"
    PERFORMANCE_METRICS = "crypto/metrics"

class SecurityLevel(Enum):
    LEVEL_1 = 1  # AES-128 equivalent
    LEVEL_3 = 3  # AES-192 equivalent  
    LEVEL_5 = 5  # AES-256 equivalent

class MQTTSecureCommunicator:
    def __init__(self, client_id, is_drone=True, broker_host="localhost", broker_port=8883):
        """
        Initialize secure MQTT communicator
        
        Args:
            client_id: Unique client identifier
            is_drone: True for drone, False for GCS
            broker_host: MQTT broker hostname
            broker_port: MQTT broker port (8883 for TLS)
        """
        self.client_id = client_id
        self.is_drone = is_drone
        self.broker_host = broker_host
        self.broker_port = broker_port
        
        # MQTT client setup
        self.client = mqtt.Client(client_id=client_id, protocol=mqtt.MQTTv311)
        self.client.on_connect = self._on_connect
        self.client.on_disconnect = self._on_disconnect
        self.client.on_message = self._on_message
        
        # Current algorithm tracking
        self.current_algorithm = "ML-KEM-768"  # Default Level 3
        self.current_level = SecurityLevel.LEVEL_3
        self.algorithm_process = None
        
        # Heartbeat monitoring
        self.heartbeat_interval = 5.0  # seconds
        self.heartbeat_thread = None
        self.heartbeat_running = False
        
        # DDoS detection state
        self.ddos_detected = False
        self.missed_heartbeats = 0
        self.max_missed_heartbeats = 5
        self.last_heartbeat_time = None
        
        # Connection state
        self.is_connected = False
        self.reconnect_interval = 5.0
        
        # Available algorithms by security level
        self.algorithms = {
            SecurityLevel.LEVEL_1: {
                "ML-KEM-512": ("level1_128bit/drone/drone_kyber_512.py", "level1_128bit/gcs/gcs_kyber_512.py"),
                "ML-DSA-44": ("level1_128bit/drone/drone_dilithium2.py", "level1_128bit/gcs/gcs_dilithium2.py"),
                "Falcon-512": ("level1_128bit/drone/drone_falcon512.py", "level1_128bit/gcs/gcs_falcon512.py"),
            },
            SecurityLevel.LEVEL_3: {
                "ML-KEM-768": ("level3_192bit/drone/drone_kyber_768.py", "level3_192bit/gcs/gcs_kyber_768.py"),
                "ML-DSA-65": ("level3_192bit/drone/drone_dilithium3.py", "level3_192bit/gcs/gcs_dilithium3.py"),
            },
            SecurityLevel.LEVEL_5: {
                "ML-KEM-1024": ("level5_256bit/drone/drone_kyber_1024.py", "level5_256bit/gcs/gcs_kyber_1024.py"),
                "ML-DSA-87": ("level5_256bit/drone/drone_dilithium5.py", "level5_256bit/gcs/gcs_dilithium5.py"),
                "Falcon-1024": ("level5_256bit/drone/drone_falcon1024.py", "level5_256bit/gcs/gcs_falcon1024.py"),
            }
        }
        
    def setup_tls(self, ca_cert_path=None, cert_file_path=None, key_file_path=None):
        """
        Setup TLS/SSL encryption for secure MQTT communication
        
        Args:
            ca_cert_path: Path to CA certificate
            cert_file_path: Path to client certificate  
            key_file_path: Path to client private key
        """
        try:
            # For testing without certificates, use insecure connection
            if not all([ca_cert_path, cert_file_path, key_file_path]):
                print("⚠️ Running in insecure mode for testing - no TLS certificates provided")
                self.broker_port = 1883  # Standard MQTT port without TLS
                return
                
            # Configure TLS context
            context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_REQUIRED
            
            # Load certificates
            if ca_cert_path and os.path.exists(ca_cert_path):
                context.load_verify_locations(ca_cert_path)
                
            if cert_file_path and key_file_path:
                context.load_cert_chain(cert_file_path, key_file_path)
            
            # Apply TLS context to MQTT client
            self.client.tls_set_context(context)
            print("🔒 TLS encryption enabled for MQTT communication")
            
        except Exception as e:
            print(f"⚠️ TLS setup failed: {e}")
            print("   Falling back to insecure connection for testing")
            self.broker_port = 1883
    
    def connect(self):
        """Connect to MQTT broker with automatic reconnection"""
        try:
            print(f"🔗 Connecting to MQTT broker at {self.broker_host}:{self.broker_port}")
            self.client.connect(self.broker_host, self.broker_port, 60)
            self.client.loop_start()
            
            # Wait for connection
            timeout = 10
            while not self.is_connected and timeout > 0:
                time.sleep(0.5)
                timeout -= 0.5
                
            if not self.is_connected:
                raise ConnectionError("Failed to connect within timeout")
                
            # Start heartbeat monitoring
            if self.is_drone:
                self._start_heartbeat_sender()
            else:
                self._start_heartbeat_monitor()
                
            print("✅ MQTT connection established")
            return True
            
        except Exception as e:
            print(f"❌ MQTT connection failed: {e}")
            return False
    
    def disconnect(self):
        """Gracefully disconnect from MQTT broker"""
        print("🔌 Disconnecting from MQTT broker...")
        
        # Stop heartbeat
        self.heartbeat_running = False
        if self.heartbeat_thread:
            self.heartbeat_thread.join(timeout=2)
            
        # Stop current algorithm process
        self._stop_current_algorithm()
        
        # Disconnect MQTT
        self.client.loop_stop()
        self.client.disconnect()
        
    def _on_connect(self, client, userdata, flags, rc):
        """Handle MQTT connection event"""
        if rc == 0:
            self.is_connected = True
            print(f"📡 MQTT connected successfully (Client: {self.client_id})")
            
            # Subscribe to relevant topics
            if self.is_drone:
                # Drone subscribes to algorithm switch commands from GCS
                client.subscribe(MQTTTopics.ALGORITHM_SWITCH, qos=2)  # Exactly once delivery
                client.subscribe(MQTTTopics.DDOS_ALERT, qos=1)       # At least once delivery
            else:
                # GCS subscribes to heartbeats and status updates from drone
                client.subscribe(MQTTTopics.HEARTBEAT, qos=1)
                client.subscribe(MQTTTopics.SYSTEM_STATUS, qos=1)
                client.subscribe(MQTTTopics.PERFORMANCE_METRICS, qos=0)  # Best effort
                
        else:
            print(f"❌ MQTT connection failed with code {rc}")
            self.is_connected = False
    
    def _on_disconnect(self, client, userdata, rc):
        """Handle MQTT disconnection event"""
        self.is_connected = False
        print(f"🔌 MQTT disconnected (Code: {rc})")
        
        # Implement automatic reconnection
        if rc != 0:  # Unexpected disconnection
            print("🔄 Attempting to reconnect...")
            threading.Timer(self.reconnect_interval, self._attempt_reconnect).start()
    
    def _attempt_reconnect(self):
        """Attempt to reconnect to MQTT broker"""
        max_attempts = 5
        attempt = 0
        
        while attempt < max_attempts and not self.is_connected:
            attempt += 1
            print(f"🔄 Reconnection attempt {attempt}/{max_attempts}")
            
            try:
                self.client.reconnect()
                time.sleep(2)
                
                if self.is_connected:
                    print("✅ Reconnection successful")
                    return
                    
            except Exception as e:
                print(f"❌ Reconnection attempt {attempt} failed: {e}")
                
            time.sleep(self.reconnect_interval * attempt)  # Exponential backoff
            
        print("❌ All reconnection attempts failed")
    
    def _on_message(self, client, userdata, msg):
        """Handle incoming MQTT messages"""
        topic = msg.topic
        payload = msg.payload.decode('utf-8')
        
        print(f"📨 Received message on {topic}: {payload[:100]}...")
        
        try:
            if topic == MQTTTopics.ALGORITHM_SWITCH and self.is_drone:
                self._handle_algorithm_switch(payload)
                
            elif topic == MQTTTopics.HEARTBEAT and not self.is_drone:
                self._handle_heartbeat_received(payload)
                
            elif topic == MQTTTopics.DDOS_ALERT:
                self._handle_ddos_alert(payload)
                
            elif topic == MQTTTopics.SYSTEM_STATUS:
                self._handle_system_status(payload)
                
        except Exception as e:
            print(f"❌ Error processing message: {e}")
    
    def _handle_algorithm_switch(self, payload):
        """Handle algorithm switch command from GCS"""
        try:
            command = json.loads(payload)
            new_algorithm = command.get('algorithm')
            priority = command.get('priority', 'normal')
            reason = command.get('reason', 'manual_switch')
            
            print(f"🔄 Algorithm switch request: {new_algorithm} (Priority: {priority}, Reason: {reason})")
            
            # Validate algorithm
            algorithm_found = False
            new_level = None
            
            for level, alg_dict in self.algorithms.items():
                if new_algorithm in alg_dict:
                    algorithm_found = True
                    new_level = level
                    break
            
            if not algorithm_found:
                print(f"❌ Unknown algorithm: {new_algorithm}")
                self._send_status_update("error", f"Unknown algorithm: {new_algorithm}")
                return
            
            # Perform algorithm switch
            success = self._switch_algorithm(new_algorithm, new_level)
            
            if success:
                self._send_status_update("algorithm_switched", {
                    "algorithm": new_algorithm,
                    "level": new_level.value,
                    "timestamp": datetime.now().isoformat(),
                    "reason": reason
                })
            else:
                self._send_status_update("switch_failed", f"Failed to switch to {new_algorithm}")
                
        except json.JSONDecodeError as e:
            print(f"❌ Invalid JSON in algorithm switch command: {e}")
            
    def _switch_algorithm(self, algorithm, level):
        """Switch to new PQC algorithm"""
        try:
            print(f"🔧 Switching to {algorithm} (Level {level.value})")
            
            # Stop current algorithm process
            self._stop_current_algorithm()
            
            # Start new algorithm process
            script_path = self.algorithms[level][algorithm][0 if self.is_drone else 1]
            
            print(f"   Starting: {script_path}")
            self.algorithm_process = subprocess.Popen([
                "python", script_path
            ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
            # Wait briefly to ensure process starts
            time.sleep(2)
            
            if self.algorithm_process.poll() is None:  # Process is running
                self.current_algorithm = algorithm
                self.current_level = level
                print(f"✅ Successfully switched to {algorithm}")
                return True
            else:
                print(f"❌ Failed to start {algorithm} process")
                return False
                
        except Exception as e:
            print(f"❌ Algorithm switch failed: {e}")
            return False
    
    def _stop_current_algorithm(self):
        """Stop currently running algorithm process"""
        if self.algorithm_process:
            try:
                print(f"🛑 Stopping current algorithm: {self.current_algorithm}")
                self.algorithm_process.terminate()
                self.algorithm_process.wait(timeout=5)
                print("✅ Algorithm process stopped")
            except subprocess.TimeoutExpired:
                print("⚠️ Force killing algorithm process")
                self.algorithm_process.kill()
            except Exception as e:
                print(f"❌ Error stopping algorithm: {e}")
            finally:
                self.algorithm_process = None
    
    def _start_heartbeat_sender(self):
        """Start heartbeat sender thread (drone side)"""
        def heartbeat_loop():
            sequence = 0
            while self.heartbeat_running:
                try:
                    heartbeat_data = {
                        "client_id": self.client_id,
                        "timestamp": datetime.now().isoformat(),
                        "sequence": sequence,
                        "algorithm": self.current_algorithm,
                        "level": self.current_level.value,
                        "status": "operational"
                    }
                    
                    self.client.publish(
                        MQTTTopics.HEARTBEAT, 
                        json.dumps(heartbeat_data), 
                        qos=1  # At least once delivery
                    )
                    
                    sequence += 1
                    time.sleep(self.heartbeat_interval)
                    
                except Exception as e:
                    print(f"❌ Heartbeat send error: {e}")
                    
        self.heartbeat_running = True
        self.heartbeat_thread = threading.Thread(target=heartbeat_loop, daemon=True)
        self.heartbeat_thread.start()
        print("💓 Heartbeat sender started")
    
    def _start_heartbeat_monitor(self):
        """Start heartbeat monitor thread (GCS side)"""
        def monitor_loop():
            while self.heartbeat_running:
                try:
                    if self.last_heartbeat_time:
                        time_since_last = datetime.now() - self.last_heartbeat_time
                        
                        if time_since_last > timedelta(seconds=self.heartbeat_interval * 2):
                            self.missed_heartbeats += 1
                            print(f"⚠️ Missed heartbeat #{self.missed_heartbeats} (last: {time_since_last})")
                            
                            if self.missed_heartbeats >= self.max_missed_heartbeats:
                                if not self.ddos_detected:
                                    self._detect_ddos_by_heartbeat()
                        else:
                            # Reset counter if heartbeat received
                            if self.missed_heartbeats > 0:
                                print("✅ Heartbeat restored")
                                self.missed_heartbeats = 0
                                self.ddos_detected = False
                    
                    time.sleep(self.heartbeat_interval)
                    
                except Exception as e:
                    print(f"❌ Heartbeat monitor error: {e}")
                    
        self.heartbeat_running = True
        self.heartbeat_thread = threading.Thread(target=monitor_loop, daemon=True)
        self.heartbeat_thread.start()
        print("🔍 Heartbeat monitor started")
    
    def _handle_heartbeat_received(self, payload):
        """Handle received heartbeat from drone"""
        try:
            heartbeat = json.loads(payload)
            self.last_heartbeat_time = datetime.now()
            
            # Reset missed heartbeat counter
            if self.missed_heartbeats > 0:
                self.missed_heartbeats = 0
                self.ddos_detected = False
                print("✅ Heartbeat connection restored")
                
        except json.JSONDecodeError as e:
            print(f"❌ Invalid heartbeat JSON: {e}")
    
    def _detect_ddos_by_heartbeat(self):
        """Detect DDoS attack based on missed heartbeats"""
        self.ddos_detected = True
        
        alert = {
            "alert_type": "ddos_heartbeat_timeout",
            "timestamp": datetime.now().isoformat(),
            "missed_heartbeats": self.missed_heartbeats,
            "detection_method": "heartbeat_monitoring",
            "severity": "high"
        }
        
        print(f"🚨 DDoS detected via heartbeat timeout: {self.missed_heartbeats} missed")
        
        # Broadcast DDoS alert
        self.client.publish(
            MQTTTopics.DDOS_ALERT,
            json.dumps(alert),
            qos=2  # Exactly once delivery for critical alerts
        )
    
    def _handle_ddos_alert(self, payload):
        """Handle DDoS alert from detection system"""
        try:
            alert = json.loads(payload)
            alert_type = alert.get('alert_type', 'unknown')
            severity = alert.get('severity', 'medium')
            
            print(f"🚨 DDoS Alert: {alert_type} (Severity: {severity})")
            
            # Implement DDoS response based on severity
            if severity == 'high':
                # Switch to maximum security algorithm
                if self.current_level != SecurityLevel.LEVEL_5:
                    print("🔒 Switching to Level 5 security due to DDoS attack")
                    # Auto-switch to strongest algorithm
                    self._switch_algorithm("ML-KEM-1024", SecurityLevel.LEVEL_5)
            
        except json.JSONDecodeError as e:
            print(f"❌ Invalid DDoS alert JSON: {e}")
    
    def _send_status_update(self, status_type, data):
        """Send system status update to GCS"""
        status = {
            "client_id": self.client_id,
            "timestamp": datetime.now().isoformat(),
            "status_type": status_type,
            "data": data,
            "current_algorithm": self.current_algorithm,
            "current_level": self.current_level.value
        }
        
        self.client.publish(
            MQTTTopics.SYSTEM_STATUS,
            json.dumps(status),
            qos=1
        )
    
    def send_algorithm_switch_command(self, algorithm, priority="normal", reason="manual"):
        """Send algorithm switch command (GCS to drone)"""
        if self.is_drone:
            print("❌ Drones cannot send algorithm switch commands")
            return False
            
        command = {
            "algorithm": algorithm,
            "priority": priority,
            "reason": reason,
            "timestamp": datetime.now().isoformat(),
            "sender": self.client_id
        }
        
        self.client.publish(
            MQTTTopics.ALGORITHM_SWITCH,
            json.dumps(command),
            qos=2  # Exactly once delivery for critical commands
        )
        
        print(f"📤 Sent algorithm switch command: {algorithm}")
        return True

def main():
    """Test MQTT communication system"""
    import argparse
    
    parser = argparse.ArgumentParser(description='MQTT Secure Communicator Test')
    parser.add_argument('--mode', choices=['drone', 'gcs'], required=True,
                       help='Run as drone or GCS')
    parser.add_argument('--broker', default='localhost',
                       help='MQTT broker hostname')
    parser.add_argument('--port', type=int, default=1883,
                       help='MQTT broker port')
    
    args = parser.parse_args()
    
    # Create communicator
    client_id = f"{args.mode}_client_{int(time.time())}"
    is_drone = (args.mode == 'drone')
    
    communicator = MQTTSecureCommunicator(
        client_id=client_id,
        is_drone=is_drone,
        broker_host=args.broker,
        broker_port=args.port
    )
    
    print(f"🚀 Starting MQTT {args.mode.upper()} communicator")
    print(f"   Client ID: {client_id}")
    print(f"   Broker: {args.broker}:{args.port}")
    
    # Connect to broker
    if not communicator.connect():
        print("❌ Failed to connect to MQTT broker")
        return
    
    try:
        if not is_drone:
            # GCS interactive mode
            print("\n🎮 GCS CONTROL INTERFACE")
            print("Commands:")
            print("  switch <algorithm> - Switch drone to specific algorithm")
            print("  status - Show current status")
            print("  quit - Exit")
            
            while True:
                try:
                    cmd = input("\nGCS> ").strip().split()
                    if not cmd:
                        continue
                        
                    if cmd[0] == 'quit':
                        break
                    elif cmd[0] == 'switch' and len(cmd) > 1:
                        algorithm = cmd[1]
                        communicator.send_algorithm_switch_command(algorithm)
                    elif cmd[0] == 'status':
                        print(f"Current algorithm: {communicator.current_algorithm}")
                        print(f"Current level: {communicator.current_level}")
                    else:
                        print("Invalid command")
                        
                except KeyboardInterrupt:
                    break
        else:
            # Drone mode - just listen for commands
            print("🔄 Drone running - listening for algorithm switch commands...")
            print("Press Ctrl+C to stop")
            
            while True:
                time.sleep(1)
                
    except KeyboardInterrupt:
        pass
    
    finally:
        print("\n🛑 Shutting down...")
        communicator.disconnect()

if __name__ == "__main__":
    main()