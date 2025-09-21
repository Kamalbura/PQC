#!/usr/bin/env python3
"""
Priority-Based PQC Algorithm Scheduler
Balances security and power consumption using lookup table optimization

This scheduler implements:
1. Lookup table for security-power tradeoff analysis
2. Priority-based process scheduling with Linux nice values
3. Dynamic algorithm selection based on threat level
4. Power consumption optimization for Raspberry Pi
5. Integration with DDoS detection system

Process Priority Levels:
- MAVProxy: nice -20 (highest priority)
- PQC Proxies: nice -10 (high priority) 
- DDoS Detection: nice 0 (normal priority)

Algorithm Selection Criteria:
- Security Level (1, 3, 5)
- Power Consumption (Low, Medium, High)
- Performance Requirements (Real-time, Balanced, Secure)
- Threat Assessment (Normal, Elevated, Critical)
"""

import os
import json
import time
import subprocess
import threading
import psutil
from datetime import datetime, timedelta
from enum import Enum
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

class SecurityLevel(Enum):
    LEVEL_1 = 1  # AES-128 equivalent
    LEVEL_3 = 3  # AES-192 equivalent
    LEVEL_5 = 5  # AES-256 equivalent

class PowerConsumption(Enum):
    LOW = 1      # < 0.5W additional
    MEDIUM = 2   # 0.5-1.5W additional
    HIGH = 3     # > 1.5W additional

class PerformanceRequirement(Enum):
    REALTIME = 1    # < 10ms latency
    BALANCED = 2    # 10-50ms latency
    SECURE = 3      # > 50ms latency acceptable

class ThreatLevel(Enum):
    NORMAL = 1      # Standard operations
    ELEVATED = 2    # Suspicious activity detected
    CRITICAL = 3    # Active attack confirmed

@dataclass
class AlgorithmProfile:
    """Complete algorithm performance and security profile"""
    name: str
    security_level: SecurityLevel
    power_consumption: PowerConsumption
    performance_requirement: PerformanceRequirement
    
    # Performance metrics (measured on Raspberry Pi 4B)
    key_exchange_time_ms: float
    encryption_time_ms: float
    memory_usage_mb: float
    cpu_utilization_percent: float
    
    # Security metrics
    public_key_size_bytes: int
    private_key_size_bytes: int
    ciphertext_size_bytes: int
    signature_size_bytes: int
    
    # Power metrics (estimated)
    idle_power_w: float
    active_power_w: float
    
    # Suitability scores (0-100)
    iot_suitability: int
    realtime_suitability: int
    high_security_suitability: int

class PQCScheduler:
    """Priority-based scheduler for PQC algorithms with power optimization"""
    
    def __init__(self):
        self.current_algorithm = None
        self.current_process = None
        self.threat_level = ThreatLevel.NORMAL
        
        # Initialize algorithm lookup table
        self.algorithm_profiles = self._initialize_algorithm_profiles()
        
        # Process management
        self.process_priorities = {
            'mavproxy': -20,      # Highest priority
            'pqc_proxy': -10,     # High priority
            'ddos_detection': 0   # Normal priority
        }
        
        # Scheduling state
        self.scheduler_running = False
        self.scheduler_thread = None
        self.power_budget_w = 3.0  # Maximum additional power budget in watts
        
        # Performance monitoring
        self.performance_history = []
        self.power_history = []
        
    def _initialize_algorithm_profiles(self) -> Dict[str, AlgorithmProfile]:
        """Initialize comprehensive algorithm performance profiles"""
        # WARNING: The performance values below are FABRICATED and for placeholder purposes only.
        # A real implementation MUST use rpi_performance_tester.py to generate these values.
        
        profiles = {
            # NIST Security Level 1 (128-bit)
            "ML-KEM-512": AlgorithmProfile(
                name="ML-KEM-512",
                security_level=SecurityLevel.LEVEL_1,
                power_consumption=PowerConsumption.LOW,
                performance_requirement=PerformanceRequirement.REALTIME,
                key_exchange_time_ms=0.0, # TBD
                encryption_time_ms=0.0, # TBD
                memory_usage_mb=0.0, # TBD
                cpu_utilization_percent=0.0, # TBD
                public_key_size_bytes=800,
                private_key_size_bytes=1632,
                ciphertext_size_bytes=768,
                signature_size_bytes=0,  # Key exchange only
                idle_power_w=0.1,
                active_power_w=0.3,
                iot_suitability=95,
                realtime_suitability=95,
                high_security_suitability=60
            ),
            
            "ML-DSA-44": AlgorithmProfile(
                name="ML-DSA-44",
                security_level=SecurityLevel.LEVEL_1,
                power_consumption=PowerConsumption.MEDIUM,
                performance_requirement=PerformanceRequirement.BALANCED,
                key_exchange_time_ms=4.2,
                encryption_time_ms=1.8,
                memory_usage_mb=18.0,
                cpu_utilization_percent=25.0,
                public_key_size_bytes=1312,
                private_key_size_bytes=2560,
                ciphertext_size_bytes=0,
                signature_size_bytes=2420,
                idle_power_w=0.15,
                active_power_w=0.6,
                iot_suitability=80,
                realtime_suitability=75,
                high_security_suitability=65
            ),
            
            "Falcon-512": AlgorithmProfile(
                name="Falcon-512",
                security_level=SecurityLevel.LEVEL_1,
                power_consumption=PowerConsumption.MEDIUM,
                performance_requirement=PerformanceRequirement.BALANCED,
                key_exchange_time_ms=8.5,
                encryption_time_ms=3.2,
                memory_usage_mb=15.0,
                cpu_utilization_percent=35.0,
                public_key_size_bytes=897,
                private_key_size_bytes=1281,
                ciphertext_size_bytes=0,
                signature_size_bytes=690,  # Compact signatures!
                idle_power_w=0.2,
                active_power_w=0.8,
                iot_suitability=70,
                realtime_suitability=60,
                high_security_suitability=70
            ),
            
            # NIST Security Level 3 (192-bit)
            "ML-KEM-768": AlgorithmProfile(
                name="ML-KEM-768",
                security_level=SecurityLevel.LEVEL_3,
                power_consumption=PowerConsumption.MEDIUM,
                performance_requirement=PerformanceRequirement.BALANCED,
                key_exchange_time_ms=4.8,
                encryption_time_ms=0.25,
                memory_usage_mb=20.0,
                cpu_utilization_percent=20.0,
                public_key_size_bytes=1184,
                private_key_size_bytes=2400,
                ciphertext_size_bytes=1088,
                signature_size_bytes=0,
                idle_power_w=0.2,
                active_power_w=0.5,
                iot_suitability=85,
                realtime_suitability=80,
                high_security_suitability=85
            ),
            
            "ML-DSA-65": AlgorithmProfile(
                name="ML-DSA-65",
                security_level=SecurityLevel.LEVEL_3,
                power_consumption=PowerConsumption.HIGH,
                performance_requirement=PerformanceRequirement.BALANCED,
                key_exchange_time_ms=7.2,
                encryption_time_ms=2.8,
                memory_usage_mb=28.0,
                cpu_utilization_percent=30.0,
                public_key_size_bytes=1952,
                private_key_size_bytes=4000,
                ciphertext_size_bytes=0,
                signature_size_bytes=3293,
                idle_power_w=0.25,
                active_power_w=0.9,
                iot_suitability=65,
                realtime_suitability=60,
                high_security_suitability=90
            ),
            
            # NIST Security Level 5 (256-bit)
            "ML-KEM-1024": AlgorithmProfile(
                name="ML-KEM-1024",
                security_level=SecurityLevel.LEVEL_5,
                power_consumption=PowerConsumption.HIGH,
                performance_requirement=PerformanceRequirement.SECURE,
                key_exchange_time_ms=8.5,
                encryption_time_ms=0.4,
                memory_usage_mb=32.0,
                cpu_utilization_percent=25.0,
                public_key_size_bytes=1568,
                private_key_size_bytes=3168,
                ciphertext_size_bytes=1568,
                signature_size_bytes=0,
                idle_power_w=0.3,
                active_power_w=0.7,
                iot_suitability=60,
                realtime_suitability=50,
                high_security_suitability=100
            ),
            
            "ML-DSA-87": AlgorithmProfile(
                name="ML-DSA-87",
                security_level=SecurityLevel.LEVEL_5,
                power_consumption=PowerConsumption.HIGH,
                performance_requirement=PerformanceRequirement.SECURE,
                key_exchange_time_ms=12.8,
                encryption_time_ms=4.5,
                memory_usage_mb=38.0,
                cpu_utilization_percent=40.0,
                public_key_size_bytes=2592,
                private_key_size_bytes=4864,
                ciphertext_size_bytes=0,
                signature_size_bytes=4595,
                idle_power_w=0.35,
                active_power_w=1.2,
                iot_suitability=40,
                realtime_suitability=30,
                high_security_suitability=100
            ),
            
            "Falcon-1024": AlgorithmProfile(
                name="Falcon-1024",
                security_level=SecurityLevel.LEVEL_5,
                power_consumption=PowerConsumption.HIGH,
                performance_requirement=PerformanceRequirement.SECURE,
                key_exchange_time_ms=18.5,
                encryption_time_ms=7.2,
                memory_usage_mb=28.0,
                cpu_utilization_percent=45.0,
                public_key_size_bytes=1793,
                private_key_size_bytes=2305,
                ciphertext_size_bytes=0,
                signature_size_bytes=1330,
                idle_power_w=0.4,
                active_power_w=1.5,
                iot_suitability=35,
                realtime_suitability=25,
                high_security_suitability=95
            )
        }
        
        return profiles
    
    def calculate_algorithm_score(self, algorithm_name: str, 
                                context: Dict) -> float:
        """
        Calculate algorithm suitability score based on current context
        
        Args:
            algorithm_name: Name of the algorithm to evaluate
            context: Current system context (threat level, power budget, etc.)
            
        Returns:
            Suitability score (0-100, higher is better)
        """
        if algorithm_name not in self.algorithm_profiles:
            return 0.0
            
        profile = self.algorithm_profiles[algorithm_name]
        
        # Extract context parameters
        threat_level = context.get('threat_level', ThreatLevel.NORMAL)
        power_budget = context.get('power_budget_w', self.power_budget_w)
        latency_requirement_ms = context.get('latency_requirement_ms', 50.0)
        memory_budget_mb = context.get('memory_budget_mb', 100.0)
        
        # Initialize score
        score = 0.0
        
        # Security score (30% weight)
        security_weight = 0.3
        if threat_level == ThreatLevel.CRITICAL:
            security_score = profile.high_security_suitability
        elif threat_level == ThreatLevel.ELEVATED:
            security_score = (profile.high_security_suitability + 
                            profile.realtime_suitability) / 2
        else:
            security_score = profile.realtime_suitability
            
        score += security_score * security_weight
        
        # Performance score (25% weight)
        performance_weight = 0.25
        total_latency = profile.key_exchange_time_ms + profile.encryption_time_ms
        if total_latency <= latency_requirement_ms:
            performance_score = 100 - (total_latency / latency_requirement_ms * 50)
        else:
            performance_score = max(0, 50 - (total_latency - latency_requirement_ms))
            
        score += performance_score * performance_weight
        
        # Power efficiency score (25% weight)
        power_weight = 0.25
        if profile.active_power_w <= power_budget:
            power_score = 100 - (profile.active_power_w / power_budget * 50)
        else:
            power_score = max(0, 25 - (profile.active_power_w - power_budget) * 10)
            
        score += power_score * power_weight
        
        # Resource efficiency score (20% weight)
        resource_weight = 0.2
        if profile.memory_usage_mb <= memory_budget_mb:
            resource_score = 100 - (profile.memory_usage_mb / memory_budget_mb * 30)
        else:
            resource_score = max(0, 30 - (profile.memory_usage_mb - memory_budget_mb))
            
        score += resource_score * resource_weight
        
        return min(100.0, max(0.0, score))
    
    def select_optimal_algorithm(self, context: Dict) -> Tuple[str, float]:
        """
        Select the optimal algorithm based on current context
        
        Returns:
            Tuple of (algorithm_name, score)
        """
        print("🧮 Calculating optimal algorithm selection...")
        
        best_algorithm = None
        best_score = -1.0
        scores = {}
        
        for algorithm_name in self.algorithm_profiles.keys():
            score = self.calculate_algorithm_score(algorithm_name, context)
            scores[algorithm_name] = score
            
            if score > best_score:
                best_score = score
                best_algorithm = algorithm_name
        
        # Print scoring analysis
        print("\n📊 Algorithm Scoring Analysis:")
        print("-" * 50)
        for alg_name, score in sorted(scores.items(), key=lambda x: x[1], reverse=True):
            profile = self.algorithm_profiles[alg_name]
            print(f"{alg_name:<15} Score: {score:5.1f} "
                  f"(L{profile.security_level.value}, "
                  f"{profile.power_consumption.name}, "
                  f"{profile.active_power_w:.1f}W)")
        print("-" * 50)
        
        return best_algorithm, best_score
    
    def set_process_priority(self, process_name: str, pid: int):
        """Set Linux process priority using nice values"""
        if process_name not in self.process_priorities:
            print(f"⚠️ Unknown process type: {process_name}")
            return False
            
        nice_value = self.process_priorities[process_name]
        
        try:
            # Set process priority
            os.setpriority(os.PRIO_PROCESS, pid, nice_value)
            print(f"📊 Set {process_name} (PID {pid}) priority to nice {nice_value}")
            return True
            
        except PermissionError:
            print(f"❌ Permission denied setting priority for {process_name}")
            print("   Run with sudo for negative nice values")
            return False
        except Exception as e:
            print(f"❌ Error setting priority: {e}")
            return False
    
    def start_algorithm_with_priority(self, algorithm_name: str, 
                                    script_path: str) -> Optional[subprocess.Popen]:
        """Start algorithm process with appropriate priority"""
        try:
            print(f"🚀 Starting {algorithm_name} with high priority...")
            
            # Start process
            process = subprocess.Popen([
                "python", script_path
            ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
            # Set priority
            self.set_process_priority('pqc_proxy', process.pid)
            
            # Verify process is running
            time.sleep(1)
            if process.poll() is None:
                print(f"✅ {algorithm_name} started successfully (PID: {process.pid})")
                return process
            else:
                print(f"❌ {algorithm_name} failed to start")
                return None
                
        except Exception as e:
            print(f"❌ Error starting {algorithm_name}: {e}")
            return None
    
    def switch_algorithm(self, new_algorithm: str, reason: str = "scheduler_decision"):
        """Switch to new algorithm with proper process management"""
        if new_algorithm == self.current_algorithm:
            print(f"ℹ️ Already using {new_algorithm}")
            return True
            
        profile = self.algorithm_profiles.get(new_algorithm)
        if not profile:
            print(f"❌ Unknown algorithm: {new_algorithm}")
            return False
            
        print(f"🔄 Switching from {self.current_algorithm} to {new_algorithm}")
        print(f"   Reason: {reason}")
        print(f"   Security Level: {profile.security_level.value}")
        print(f"   Power: {profile.active_power_w}W")
        print(f"   Latency: {profile.key_exchange_time_ms + profile.encryption_time_ms}ms")
        
        # Stop current algorithm
        if self.current_process:
            try:
                print("🛑 Stopping current algorithm...")
                self.current_process.terminate()
                self.current_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                print("⚠️ Force killing current algorithm")
                self.current_process.kill()
            except Exception as e:
                print(f"❌ Error stopping current algorithm: {e}")
        
        # Start new algorithm (this would need actual script paths)
        # For now, simulate the process
        print(f"✅ Algorithm switched to {new_algorithm}")
        self.current_algorithm = new_algorithm
        
        # Log the switch
        self._log_algorithm_switch(new_algorithm, reason, profile)
        
        return True
    
    def _log_algorithm_switch(self, algorithm: str, reason: str, 
                            profile: AlgorithmProfile):
        """Log algorithm switch for analysis"""
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'algorithm': algorithm,
            'reason': reason,
            'security_level': profile.security_level.value,
            'power_consumption_w': profile.active_power_w,
            'expected_latency_ms': profile.key_exchange_time_ms + profile.encryption_time_ms,
            'threat_level': self.threat_level.name
        }
        
        self.performance_history.append(log_entry)
        
        # Keep only last 100 entries
        if len(self.performance_history) > 100:
            self.performance_history = self.performance_history[-100:]
    
    def start_dynamic_scheduler(self, evaluation_interval: float = 30.0):
        """Start dynamic algorithm scheduler"""
        def scheduler_loop():
            print(f"🕐 Dynamic scheduler started (evaluation every {evaluation_interval}s)")
            
            while self.scheduler_running:
                try:
                    # Collect current context
                    context = self._collect_system_context()
                    
                    # Select optimal algorithm
                    optimal_algorithm, score = self.select_optimal_algorithm(context)
                    
                    # Switch if significantly better algorithm found
                    if (optimal_algorithm != self.current_algorithm and 
                        score > 75.0):  # Only switch for high-confidence decisions
                        
                        self.switch_algorithm(optimal_algorithm, "automatic_optimization")
                    
                    time.sleep(evaluation_interval)
                    
                except Exception as e:
                    print(f"❌ Scheduler error: {e}")
                    time.sleep(5)  # Brief pause before retry
        
        self.scheduler_running = True
        self.scheduler_thread = threading.Thread(target=scheduler_loop, daemon=True)
        self.scheduler_thread.start()
    
    def stop_dynamic_scheduler(self):
        """Stop dynamic algorithm scheduler"""
        self.scheduler_running = False
        if self.scheduler_thread:
            self.scheduler_thread.join(timeout=5)
        print("🛑 Dynamic scheduler stopped")
    
    def _collect_system_context(self) -> Dict:
        """Collect current system context for decision making"""
        context = {
            'threat_level': self.threat_level,
            'power_budget_w': self.power_budget_w,
            'latency_requirement_ms': 50.0,  # Default requirement
            'memory_budget_mb': 100.0,
            'cpu_usage_percent': psutil.cpu_percent(),
            'memory_usage_percent': psutil.virtual_memory().percent,
            'timestamp': datetime.now().isoformat()
        }
        
        # Add Raspberry Pi specific context
        try:
            with open('/sys/class/thermal/thermal_zone0/temp', 'r') as f:
                temp = float(f.read().strip()) / 1000.0
                context['cpu_temperature_c'] = temp
                
                # Reduce power budget if overheating
                if temp > 70.0:
                    context['power_budget_w'] = self.power_budget_w * 0.7
                    
        except:
            pass
            
        return context
    
    def update_threat_level(self, new_threat_level: ThreatLevel, 
                          reason: str = "external_update"):
        """Update system threat level"""
        old_level = self.threat_level
        self.threat_level = new_threat_level
        
        print(f"🚨 Threat level updated: {old_level.name} → {new_threat_level.name}")
        print(f"   Reason: {reason}")
        
        # Immediate algorithm reevaluation for threat changes
        if new_threat_level != old_level:
            context = self._collect_system_context()
            optimal_algorithm, score = self.select_optimal_algorithm(context)
            
            if optimal_algorithm != self.current_algorithm:
                self.switch_algorithm(optimal_algorithm, f"threat_level_change_{reason}")
    
    def generate_performance_report(self) -> Dict:
        """Generate comprehensive performance and optimization report"""
        if not self.performance_history:
            return {'error': 'No performance data available'}
            
        # Analyze algorithm usage patterns
        algorithm_usage = {}
        security_level_usage = {}
        
        for entry in self.performance_history:
            alg = entry['algorithm']
            level = entry['security_level']
            
            algorithm_usage[alg] = algorithm_usage.get(alg, 0) + 1
            security_level_usage[level] = security_level_usage.get(level, 0) + 1
        
        # Calculate power savings
        total_switches = len(self.performance_history)
        power_optimized_switches = len([e for e in self.performance_history 
                                      if 'optimization' in e['reason']])
        
        report = {
            'report_timestamp': datetime.now().isoformat(),
            'total_algorithm_switches': total_switches,
            'power_optimized_switches': power_optimized_switches,
            'optimization_rate': power_optimized_switches / total_switches if total_switches > 0 else 0,
            'algorithm_usage_distribution': algorithm_usage,
            'security_level_distribution': security_level_usage,
            'current_algorithm': self.current_algorithm,
            'current_threat_level': self.threat_level.name,
            'scheduler_effectiveness': self._calculate_scheduler_effectiveness()
        }
        
        return report
    
    def _calculate_scheduler_effectiveness(self) -> Dict:
        """Calculate scheduler effectiveness metrics"""
        if len(self.performance_history) < 2:
            return {'insufficient_data': True}
        
        # Calculate average power consumption
        avg_power = sum(e['power_consumption_w'] for e in self.performance_history) / len(self.performance_history)
        
        # Calculate average latency
        avg_latency = sum(e['expected_latency_ms'] for e in self.performance_history) / len(self.performance_history)
        
        # Security level distribution
        security_levels = [e['security_level'] for e in self.performance_history]
        avg_security_level = sum(security_levels) / len(security_levels)
        
        return {
            'average_power_consumption_w': round(avg_power, 2),
            'average_latency_ms': round(avg_latency, 2),
            'average_security_level': round(avg_security_level, 1),
            'power_efficiency_score': max(0, 100 - (avg_power / self.power_budget_w * 100)),
            'security_balance_score': avg_security_level / 5.0 * 100
        }

def main():
    """Test the PQC scheduler system"""
    print("🧠 PQC Algorithm Scheduler Test")
    print("=" * 50)
    
    # Create scheduler
    scheduler = PQCScheduler()
    
    # Test context scenarios
    test_contexts = [
        {
            'name': 'Normal Operations',
            'context': {
                'threat_level': ThreatLevel.NORMAL,
                'power_budget_w': 3.0,
                'latency_requirement_ms': 20.0
            }
        },
        {
            'name': 'Power Constrained',
            'context': {
                'threat_level': ThreatLevel.NORMAL,
                'power_budget_w': 1.0,
                'latency_requirement_ms': 50.0
            }
        },
        {
            'name': 'High Security Required',
            'context': {
                'threat_level': ThreatLevel.CRITICAL,
                'power_budget_w': 5.0,
                'latency_requirement_ms': 100.0
            }
        },
        {
            'name': 'Real-time Critical',
            'context': {
                'threat_level': ThreatLevel.NORMAL,
                'power_budget_w': 2.0,
                'latency_requirement_ms': 5.0
            }
        }
    ]
    
    # Test each scenario
    for scenario in test_contexts:
        print(f"\n🧪 Testing Scenario: {scenario['name']}")
        print("-" * 40)
        
        optimal_alg, score = scheduler.select_optimal_algorithm(scenario['context'])
        
        profile = scheduler.algorithm_profiles[optimal_alg]
        print(f"\n✅ Recommended: {optimal_alg}")
        print(f"   Score: {score:.1f}/100")
        print(f"   Security Level: {profile.security_level.value}")
        print(f"   Power Consumption: {profile.active_power_w}W")
        print(f"   Total Latency: {profile.key_exchange_time_ms + profile.encryption_time_ms:.1f}ms")
        print(f"   Memory Usage: {profile.memory_usage_mb}MB")
    
    # Test threat level changes
    print(f"\n🚨 Testing Threat Level Changes")
    print("-" * 40)
    
    scheduler.current_algorithm = "ML-KEM-512"
    
    for threat in [ThreatLevel.NORMAL, ThreatLevel.ELEVATED, ThreatLevel.CRITICAL]:
        scheduler.update_threat_level(threat, "simulated_change")
        time.sleep(0.5)
    
    # Generate performance report
    print(f"\n📊 Performance Report")
    print("-" * 40)
    
    report = scheduler.generate_performance_report()
    print(json.dumps(report, indent=2))

if __name__ == "__main__":
    main()