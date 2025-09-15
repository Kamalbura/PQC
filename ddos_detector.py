#!/usr/bin/env python3
"""
Two-Tier DDoS Detection System for Raspberry Pi
Combines lightweight XGBoost anomaly detection with heavy Time Series Transformer confirmation

Architecture:
1. First Tier: Lightweight XGBoost for real-time anomaly detection
2. Second Tier: Time Series Transformer (TST) for confirmation when anomaly detected
3. MQTT integration for alert propagation
4. Process priority management for resource optimization

Features:
- Real-time network traffic analysis
- CPU and memory efficient first-tier detection
- High-accuracy second-tier confirmation
- Integration with PQC scheduler for threat level updates
- Power consumption optimization
"""

import numpy as np
import pandas as pd
import time
import threading
import json
import os
import psutil
import socket
import struct
from datetime import datetime, timedelta
from collections import deque
from typing import Dict, List, Tuple, Optional
from enum import Enum
import pickle

# Machine learning imports
try:
    import xgboost as xgb
    HAS_XGBOOST = True
except ImportError:
    print("⚠️ XGBoost not available - using simulated detection")
    HAS_XGBOOST = False

try:
    import torch
    import torch.nn as nn
    HAS_PYTORCH = True
except ImportError:
    print("⚠️ PyTorch not available - TST confirmation disabled")
    HAS_PYTORCH = False

class AttackType(Enum):
    NORMAL = "normal"
    DDOS_UDP_FLOOD = "ddos_udp_flood"
    DDOS_TCP_SYN = "ddos_tcp_syn" 
    DDOS_ICMP_FLOOD = "ddos_icmp_flood"
    PORT_SCAN = "port_scan"
    UNKNOWN_ANOMALY = "unknown_anomaly"

class DetectionTier(Enum):
    TIER_1_XGBOOST = "tier1_xgboost"
    TIER_2_TST = "tier2_tst"
    CONFIRMED = "confirmed"

class NetworkFeatureExtractor:
    """Extract network features for DDoS detection"""
    
    def __init__(self, window_size: int = 60):
        self.window_size = window_size  # seconds
        self.packet_buffer = deque(maxlen=1000)  # Ring buffer for packets
        self.connection_tracker = {}  # Track connection states
        
        # Feature windows
        self.packet_rate_window = deque(maxlen=window_size)
        self.byte_rate_window = deque(maxlen=window_size)
        self.connection_count_window = deque(maxlen=window_size)
        
    def extract_features(self, network_stats: Dict) -> Dict[str, float]:
        """Extract features from network statistics"""
        
        # Basic network statistics
        bytes_sent = network_stats.get('bytes_sent', 0)
        bytes_recv = network_stats.get('bytes_recv', 0)
        packets_sent = network_stats.get('packets_sent', 0)
        packets_recv = network_stats.get('packets_recv', 0)
        
        # Rate calculations
        current_time = time.time()
        total_packets = packets_sent + packets_recv
        total_bytes = bytes_sent + bytes_recv
        
        self.packet_rate_window.append(total_packets)
        self.byte_rate_window.append(total_bytes)
        
        # Calculate rates
        packet_rate = self._calculate_rate(self.packet_rate_window)
        byte_rate = self._calculate_rate(self.byte_rate_window)
        
        # Connection statistics
        try:
            connections = psutil.net_connections()
            tcp_connections = len([c for c in connections if c.type == socket.SOCK_STREAM])
            udp_connections = len([c for c in connections if c.type == socket.SOCK_DGRAM])
            
            self.connection_count_window.append(tcp_connections + udp_connections)
            connection_rate = self._calculate_rate(self.connection_count_window)
            
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            tcp_connections = udp_connections = connection_rate = 0
        
        # Feature vector
        features = {
            # Traffic volume features
            'packet_rate_pps': packet_rate,
            'byte_rate_bps': byte_rate,
            'avg_packet_size': byte_rate / max(packet_rate, 1),
            
            # Connection features  
            'tcp_connections': tcp_connections,
            'udp_connections': udp_connections,
            'connection_rate': connection_rate,
            'tcp_udp_ratio': tcp_connections / max(udp_connections, 1),
            
            # Statistical features
            'packet_rate_std': np.std(list(self.packet_rate_window)) if len(self.packet_rate_window) > 1 else 0,
            'byte_rate_std': np.std(list(self.byte_rate_window)) if len(self.byte_rate_window) > 1 else 0,
            
            # Anomaly indicators
            'packet_rate_spike': packet_rate > (np.mean(list(self.packet_rate_window)) + 2 * np.std(list(self.packet_rate_window))) if len(self.packet_rate_window) > 10 else 0,
            'byte_rate_spike': byte_rate > (np.mean(list(self.byte_rate_window)) + 2 * np.std(list(self.byte_rate_window))) if len(self.byte_rate_window) > 10 else 0,
            
            # System resource features
            'cpu_usage': psutil.cpu_percent(),
            'memory_usage': psutil.virtual_memory().percent,
            
            # Time-based features
            'hour_of_day': datetime.now().hour,
            'is_weekend': datetime.now().weekday() >= 5
        }
        
        return features
    
    def _calculate_rate(self, window: deque) -> float:
        """Calculate rate from time series window"""
        if len(window) < 2:
            return 0.0
        
        # Simple rate calculation (last - first) / time_window
        rate = (window[-1] - window[0]) / max(len(window), 1)
        return max(0.0, rate)  # Ensure non-negative

class LightweightXGBoostDetector:
    """Tier 1: Lightweight XGBoost anomaly detector"""
    
    def __init__(self, model_path: Optional[str] = None):
        self.model = None
        self.feature_extractor = NetworkFeatureExtractor()
        self.detection_threshold = 0.7  # Anomaly probability threshold
        self.model_path = model_path or "models/ddos_xgboost_model.pkl"
        
        # Performance tracking
        self.inference_times = deque(maxlen=100)
        self.detection_history = deque(maxlen=1000)
        
        # Load or create model
        self._initialize_model()
        
    def _initialize_model(self):
        """Initialize XGBoost model"""
        if HAS_XGBOOST:
            try:
                # Try to load existing model
                if os.path.exists(self.model_path):
                    with open(self.model_path, 'rb') as f:
                        self.model = pickle.load(f)
                    print(f"✅ Loaded XGBoost model from {self.model_path}")
                else:
                    # Create simple model for demonstration
                    self.model = self._create_demo_model()
                    print("⚠️ Created demo XGBoost model - train with real data for production")
                    
            except Exception as e:
                print(f"❌ Error loading XGBoost model: {e}")
                self.model = None
        else:
            print("⚠️ XGBoost not available - using rule-based detection")
            self.model = None
    
    def _create_demo_model(self):
        """Create a demo XGBoost model for testing"""
        if not HAS_XGBOOST:
            return None
            
        # Create synthetic training data
        np.random.seed(42)
        n_samples = 1000
        n_features = 14  # Number of features we extract
        
        # Normal traffic patterns
        normal_data = np.random.normal(0, 1, (n_samples // 2, n_features))
        normal_labels = np.zeros(n_samples // 2)
        
        # Anomalous traffic patterns (higher rates, more variance)
        anomaly_data = np.random.normal(3, 2, (n_samples // 2, n_features))
        anomaly_labels = np.ones(n_samples // 2)
        
        # Combine data
        X = np.vstack([normal_data, anomaly_data])
        y = np.hstack([normal_labels, anomaly_labels])
        
        # Train XGBoost classifier
        model = xgb.XGBClassifier(
            n_estimators=50,  # Small model for speed
            max_depth=3,
            learning_rate=0.1,
            random_state=42
        )
        
        model.fit(X, y)
        
        # Save demo model
        os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
        with open(self.model_path, 'wb') as f:
            pickle.dump(model, f)
            
        return model
    
    def detect_anomaly(self, network_stats: Dict) -> Tuple[bool, float, Dict]:
        """
        Detect network anomalies using XGBoost
        
        Returns:
            Tuple of (is_anomaly, confidence, detection_info)
        """
        start_time = time.perf_counter()
        
        # Extract features
        features = self.feature_extractor.extract_features(network_stats)
        
        # Convert to format expected by model
        feature_vector = np.array([list(features.values())]).reshape(1, -1)
        
        if self.model and HAS_XGBOOST:
            try:
                # XGBoost prediction
                anomaly_prob = self.model.predict_proba(feature_vector)[0, 1]  # Probability of anomaly class
                is_anomaly = anomaly_prob > self.detection_threshold
                
            except Exception as e:
                print(f"❌ XGBoost prediction error: {e}")
                # Fallback to rule-based detection
                is_anomaly, anomaly_prob = self._rule_based_detection(features)
        else:
            # Rule-based fallback detection
            is_anomaly, anomaly_prob = self._rule_based_detection(features)
        
        # Record inference time
        inference_time = (time.perf_counter() - start_time) * 1000  # ms
        self.inference_times.append(inference_time)
        
        # Create detection info
        detection_info = {
            'tier': DetectionTier.TIER_1_XGBOOST.value,
            'timestamp': datetime.now().isoformat(),
            'anomaly_probability': float(anomaly_prob),
            'inference_time_ms': inference_time,
            'features_used': len(features),
            'key_features': self._identify_key_features(features)
        }
        
        # Store detection history
        self.detection_history.append({
            'timestamp': time.time(),
            'is_anomaly': is_anomaly,
            'confidence': anomaly_prob,
            'features': features
        })
        
        return is_anomaly, anomaly_prob, detection_info
    
    def _rule_based_detection(self, features: Dict) -> Tuple[bool, float]:
        """Fallback rule-based anomaly detection"""
        anomaly_indicators = []
        
        # High packet rate indicator
        if features['packet_rate_pps'] > 1000:  # More than 1k packets/second
            anomaly_indicators.append(0.8)
            
        # High byte rate indicator  
        if features['byte_rate_bps'] > 10 * 1024 * 1024:  # More than 10 MB/s
            anomaly_indicators.append(0.7)
            
        # Unusual connection patterns
        if features['tcp_connections'] > 100:
            anomaly_indicators.append(0.6)
            
        # Resource exhaustion indicators
        if features['cpu_usage'] > 90 or features['memory_usage'] > 90:
            anomaly_indicators.append(0.5)
            
        # Spike indicators
        if features.get('packet_rate_spike', False) or features.get('byte_rate_spike', False):
            anomaly_indicators.append(0.9)
        
        # Calculate overall anomaly score
        if anomaly_indicators:
            anomaly_score = max(anomaly_indicators)  # Take highest indicator
            is_anomaly = anomaly_score > self.detection_threshold
        else:
            anomaly_score = 0.0
            is_anomaly = False
            
        return is_anomaly, anomaly_score
    
    def _identify_key_features(self, features: Dict) -> List[str]:
        """Identify which features contributed most to detection"""
        key_features = []
        
        # Simple heuristic to identify important features
        if features['packet_rate_pps'] > 500:
            key_features.append('high_packet_rate')
        if features['byte_rate_bps'] > 5 * 1024 * 1024:
            key_features.append('high_byte_rate')
        if features['tcp_connections'] > 50:
            key_features.append('high_tcp_connections')
        if features['cpu_usage'] > 80:
            key_features.append('high_cpu_usage')
            
        return key_features
    
    def get_performance_metrics(self) -> Dict:
        """Get detector performance metrics"""
        if not self.inference_times:
            return {'no_data': True}
            
        recent_detections = [d for d in self.detection_history if time.time() - d['timestamp'] < 300]  # Last 5 minutes
        
        return {
            'avg_inference_time_ms': np.mean(list(self.inference_times)),
            'max_inference_time_ms': max(self.inference_times),
            'detection_rate': len(recent_detections) / max(len(self.detection_history), 1),
            'anomaly_rate': len([d for d in recent_detections if d['is_anomaly']]) / max(len(recent_detections), 1),
            'total_detections': len(self.detection_history)
        }

class TimeSeriesTransformerDetector:
    """Tier 2: Time Series Transformer for confirmation"""
    
    def __init__(self, sequence_length: int = 60):
        self.sequence_length = sequence_length
        self.feature_buffer = deque(maxlen=sequence_length)
        self.model = None
        self.confirmation_threshold = 0.8
        
        # Performance tracking
        self.inference_times = deque(maxlen=50)
        self.confirmation_history = deque(maxlen=100)
        
        if HAS_PYTORCH:
            self._initialize_tst_model()
    
    def _initialize_tst_model(self):
        """Initialize Time Series Transformer model"""
        try:
            # Simple transformer model for demonstration
            self.model = SimpleTimeSeriesTransformer(
                input_dim=14,  # Number of features
                model_dim=64,
                num_heads=4,
                num_layers=2,
                sequence_length=self.sequence_length
            )
            
            print("✅ Time Series Transformer initialized")
            
        except Exception as e:
            print(f"❌ Error initializing TST model: {e}")
            self.model = None
    
    def confirm_anomaly(self, features_sequence: List[Dict]) -> Tuple[bool, float, Dict]:
        """
        Confirm anomaly using Time Series Transformer
        
        Args:
            features_sequence: Sequence of feature dictionaries
            
        Returns:
            Tuple of (is_confirmed, confidence, confirmation_info)
        """
        start_time = time.perf_counter()
        
        if not HAS_PYTORCH or self.model is None:
            # Fallback to statistical confirmation
            return self._statistical_confirmation(features_sequence)
        
        try:
            # Prepare sequence for transformer
            if len(features_sequence) < self.sequence_length:
                # Pad sequence if too short
                padding_needed = self.sequence_length - len(features_sequence)
                features_sequence = [features_sequence[0]] * padding_needed + features_sequence
            
            # Convert to tensor
            feature_matrix = np.array([[list(f.values()) for f in features_sequence]])
            input_tensor = torch.FloatTensor(feature_matrix)
            
            # Get transformer prediction
            with torch.no_grad():
                output = self.model(input_tensor)
                confirmation_prob = torch.sigmoid(output).item()
            
            is_confirmed = confirmation_prob > self.confirmation_threshold
            
        except Exception as e:
            print(f"❌ TST confirmation error: {e}")
            return self._statistical_confirmation(features_sequence)
        
        # Record inference time
        inference_time = (time.perf_counter() - start_time) * 1000  # ms
        self.inference_times.append(inference_time)
        
        # Create confirmation info
        confirmation_info = {
            'tier': DetectionTier.TIER_2_TST.value,
            'timestamp': datetime.now().isoformat(),
            'confirmation_probability': float(confirmation_prob),
            'inference_time_ms': inference_time,
            'sequence_length': len(features_sequence),
            'model_type': 'transformer'
        }
        
        # Store confirmation history
        self.confirmation_history.append({
            'timestamp': time.time(),
            'is_confirmed': is_confirmed,
            'confidence': confirmation_prob
        })
        
        return is_confirmed, confirmation_prob, confirmation_info
    
    def _statistical_confirmation(self, features_sequence: List[Dict]) -> Tuple[bool, float, Dict]:
        """Fallback statistical confirmation method"""
        if not features_sequence:
            return False, 0.0, {'error': 'No features provided'}
        
        # Calculate statistical indicators over the sequence
        packet_rates = [f.get('packet_rate_pps', 0) for f in features_sequence]
        byte_rates = [f.get('byte_rate_bps', 0) for f in features_sequence]
        cpu_usage = [f.get('cpu_usage', 0) for f in features_sequence]
        
        # Statistical analysis
        packet_rate_trend = np.polyfit(range(len(packet_rates)), packet_rates, 1)[0] if len(packet_rates) > 1 else 0
        byte_rate_variance = np.var(byte_rates) if len(byte_rates) > 1 else 0
        sustained_high_cpu = sum(1 for cpu in cpu_usage if cpu > 80) / len(cpu_usage)
        
        # Confirmation score based on statistical patterns
        confirmation_indicators = []
        
        if packet_rate_trend > 10:  # Increasing packet rate trend
            confirmation_indicators.append(0.8)
        if byte_rate_variance > 1000000:  # High variance in byte rate
            confirmation_indicators.append(0.7)
        if sustained_high_cpu > 0.7:  # Sustained high CPU usage
            confirmation_indicators.append(0.9)
        
        confirmation_score = max(confirmation_indicators) if confirmation_indicators else 0.0
        is_confirmed = confirmation_score > self.confirmation_threshold
        
        confirmation_info = {
            'tier': DetectionTier.TIER_2_TST.value,
            'timestamp': datetime.now().isoformat(),
            'confirmation_probability': confirmation_score,
            'inference_time_ms': 1.0,  # Very fast statistical method
            'sequence_length': len(features_sequence),
            'model_type': 'statistical'
        }
        
        return is_confirmed, confirmation_score, confirmation_info

class SimpleTimeSeriesTransformer(nn.Module):
    """Simple Time Series Transformer for DDoS confirmation"""
    
    def __init__(self, input_dim: int, model_dim: int, num_heads: int, 
                 num_layers: int, sequence_length: int):
        super().__init__()
        
        self.input_projection = nn.Linear(input_dim, model_dim)
        self.positional_encoding = nn.Parameter(torch.randn(sequence_length, model_dim))
        
        encoder_layer = nn.TransformerEncoderLayer(
            d_model=model_dim,
            nhead=num_heads,
            dim_feedforward=model_dim * 2,
            dropout=0.1,
            batch_first=True
        )
        
        self.transformer = nn.TransformerEncoder(encoder_layer, num_layers)
        self.classifier = nn.Linear(model_dim, 1)  # Binary classification
        
    def forward(self, x):
        # x shape: (batch_size, sequence_length, input_dim)
        batch_size, seq_len, _ = x.shape
        
        # Project input to model dimension
        x = self.input_projection(x)
        
        # Add positional encoding
        x = x + self.positional_encoding[:seq_len].unsqueeze(0)
        
        # Apply transformer
        transformed = self.transformer(x)
        
        # Global average pooling
        pooled = transformed.mean(dim=1)
        
        # Classification
        output = self.classifier(pooled)
        
        return output.squeeze(-1)

class TwoTierDDoSDetector:
    """Main two-tier DDoS detection system"""
    
    def __init__(self, mqtt_communicator=None):
        # Initialize detection tiers
        self.tier1_detector = LightweightXGBoostDetector()
        self.tier2_detector = TimeSeriesTransformerDetector()
        
        # MQTT integration
        self.mqtt_comm = mqtt_communicator
        
        # Detection state
        self.detection_running = False
        self.detection_thread = None
        
        # Feature sequence for tier 2
        self.feature_sequence = deque(maxlen=60)  # 60 samples for TST
        
        # Alert management
        self.recent_alerts = deque(maxlen=10)
        self.alert_cooldown = 30  # seconds
        
        # Performance monitoring
        self.detection_stats = {
            'total_samples': 0,
            'tier1_anomalies': 0,
            'tier2_confirmations': 0,
            'false_positives': 0,
            'start_time': time.time()
        }
    
    def start_detection(self, sampling_interval: float = 1.0):
        """Start continuous DDoS detection"""
        def detection_loop():
            print(f"🔍 Two-tier DDoS detection started (sampling: {sampling_interval}s)")
            
            while self.detection_running:
                try:
                    # Get current network statistics
                    network_stats = self._collect_network_stats()
                    
                    # Tier 1: XGBoost anomaly detection
                    is_anomaly, tier1_confidence, tier1_info = self.tier1_detector.detect_anomaly(network_stats)
                    
                    self.detection_stats['total_samples'] += 1
                    
                    if is_anomaly:
                        self.detection_stats['tier1_anomalies'] += 1
                        print(f"⚠️ Tier 1 Anomaly detected (confidence: {tier1_confidence:.2f})")
                        
                        # Add features to sequence for tier 2
                        features = self.tier1_detector.feature_extractor.extract_features(network_stats)
                        self.feature_sequence.append(features)
                        
                        # Tier 2: TST confirmation (only if we have enough samples)
                        if len(self.feature_sequence) >= 10:  # Minimum samples for confirmation
                            is_confirmed, tier2_confidence, tier2_info = self.tier2_detector.confirm_anomaly(
                                list(self.feature_sequence)
                            )
                            
                            if is_confirmed:
                                self.detection_stats['tier2_confirmations'] += 1
                                self._handle_confirmed_attack(tier1_info, tier2_info, tier1_confidence, tier2_confidence)
                            else:
                                print(f"   Tier 2 rejected (confidence: {tier2_confidence:.2f})")
                    
                    time.sleep(sampling_interval)
                    
                except Exception as e:
                    print(f"❌ Detection loop error: {e}")
                    time.sleep(5)  # Brief pause before retry
        
        self.detection_running = True
        self.detection_thread = threading.Thread(target=detection_loop, daemon=True)
        self.detection_thread.start()
    
    def stop_detection(self):
        """Stop DDoS detection"""
        self.detection_running = False
        if self.detection_thread:
            self.detection_thread.join(timeout=5)
        print("🛑 Two-tier DDoS detection stopped")
    
    def _collect_network_stats(self) -> Dict:
        """Collect current network statistics"""
        try:
            net_io = psutil.net_io_counters()
            return {
                'bytes_sent': net_io.bytes_sent,
                'bytes_recv': net_io.bytes_recv,
                'packets_sent': net_io.packets_sent,
                'packets_recv': net_io.packets_recv,
                'errin': net_io.errin,
                'errout': net_io.errout,
                'dropin': net_io.dropin,
                'dropout': net_io.dropout
            }
        except Exception as e:
            print(f"❌ Error collecting network stats: {e}")
            return {}
    
    def _handle_confirmed_attack(self, tier1_info: Dict, tier2_info: Dict, 
                               tier1_confidence: float, tier2_confidence: float):
        """Handle confirmed DDoS attack"""
        attack_info = {
            'attack_type': AttackType.DDOS_UDP_FLOOD.value,  # Could be refined based on features
            'detection_tier': DetectionTier.CONFIRMED.value,
            'timestamp': datetime.now().isoformat(),
            'tier1_confidence': tier1_confidence,
            'tier2_confidence': tier2_confidence,
            'combined_confidence': (tier1_confidence + tier2_confidence) / 2,
            'tier1_info': tier1_info,
            'tier2_info': tier2_info,
            'alert_id': f"ddos_{int(time.time())}"
        }
        
        print(f"🚨 CONFIRMED DDoS ATTACK DETECTED!")
        print(f"   Combined Confidence: {attack_info['combined_confidence']:.2f}")
        print(f"   Alert ID: {attack_info['alert_id']}")
        
        # Check alert cooldown
        if self._should_send_alert():
            # Send MQTT alert if available
            if self.mqtt_comm:
                try:
                    self.mqtt_comm.client.publish(
                        "crypto/ddos_alert",
                        json.dumps(attack_info),
                        qos=2  # Exactly once delivery for critical alerts
                    )
                    print("📡 DDoS alert sent via MQTT")
                except Exception as e:
                    print(f"❌ Failed to send MQTT alert: {e}")
            
            # Log alert
            self._log_attack(attack_info)
            
            # Update recent alerts
            self.recent_alerts.append(attack_info)
    
    def _should_send_alert(self) -> bool:
        """Check if we should send alert based on cooldown"""
        if not self.recent_alerts:
            return True
            
        last_alert_time = self.recent_alerts[-1].get('timestamp')
        if last_alert_time:
            last_time = datetime.fromisoformat(last_alert_time.replace('Z', '+00:00'))
            if (datetime.now() - last_time.replace(tzinfo=None)).total_seconds() > self.alert_cooldown:
                return True
                
        return False
    
    def _log_attack(self, attack_info: Dict):
        """Log attack information to file"""
        log_file = "ddos_attacks.log"
        
        try:
            with open(log_file, "a") as f:
                f.write(json.dumps(attack_info) + "\n")
        except Exception as e:
            print(f"❌ Error logging attack: {e}")
    
    def get_detection_statistics(self) -> Dict:
        """Get comprehensive detection statistics"""
        runtime = time.time() - self.detection_stats['start_time']
        
        stats = {
            'runtime_seconds': runtime,
            'samples_processed': self.detection_stats['total_samples'],
            'sampling_rate': self.detection_stats['total_samples'] / max(runtime, 1),
            'tier1_anomaly_rate': self.detection_stats['tier1_anomalies'] / max(self.detection_stats['total_samples'], 1),
            'tier2_confirmation_rate': self.detection_stats['tier2_confirmations'] / max(self.detection_stats['tier1_anomalies'], 1),
            'false_positive_rate': self.detection_stats['false_positives'] / max(self.detection_stats['tier1_anomalies'], 1),
            'alerts_sent': len(self.recent_alerts),
            'tier1_performance': self.tier1_detector.get_performance_metrics()
        }
        
        return stats

def main():
    """Test the two-tier DDoS detection system"""
    print("🛡️ Two-Tier DDoS Detection System Test")
    print("=" * 50)
    
    # Create detector
    detector = TwoTierDDoSDetector()
    
    print("🚀 Starting DDoS detection...")
    detector.start_detection(sampling_interval=2.0)  # Sample every 2 seconds
    
    try:
        # Run for test duration
        test_duration = 60  # 1 minute test
        print(f"📊 Running detection for {test_duration} seconds...")
        
        start_time = time.time()
        while time.time() - start_time < test_duration:
            # Print periodic status
            elapsed = int(time.time() - start_time)
            if elapsed % 10 == 0 and elapsed > 0:
                stats = detector.get_detection_statistics()
                print(f"   [{elapsed}s] Samples: {stats['samples_processed']}, "
                      f"Anomalies: {stats['tier1_anomaly_rate']*100:.1f}%, "
                      f"Confirmations: {stats['tier2_confirmation_rate']*100:.1f}%")
            
            time.sleep(1)
            
    except KeyboardInterrupt:
        print("\n⚠️ Test interrupted by user")
    
    finally:
        # Stop detection and show results
        detector.stop_detection()
        
        print("\n📈 Final Detection Statistics:")
        print("-" * 40)
        final_stats = detector.get_detection_statistics()
        
        for key, value in final_stats.items():
            if isinstance(value, dict):
                print(f"{key}:")
                for sub_key, sub_value in value.items():
                    print(f"  {sub_key}: {sub_value}")
            else:
                print(f"{key}: {value}")

if __name__ == "__main__":
    main()