#!/usr/bin/env python3
"""
Quick Test - Single Algorithm with Dummy Apps
Tests one PQC algorithm to verify the dummy app setup works

Usage: python quick_test_single_algorithm.py [algorithm_name]
Example: python quick_test_single_algorithm.py ML-KEM-768
"""

import subprocess
import time
import sys
import os
from datetime import datetime

def main():
    # Algorithm selection
    algorithm_choice = sys.argv[1] if len(sys.argv) > 1 else "ML-KEM-768"
    
    # Available algorithms
    algorithms = {
        "ML-KEM-512": ("drone\\drone_kyber_512.py", "gcs\\gcs_kyber_512.py"),
        "ML-KEM-768": ("drone\\drone_kyber_768.py", "gcs\\gcs_kyber_768.py"),
        "ML-KEM-1024": ("drone\\drone_kyber_1024.py", "gcs\\gcs_kyber_1024.py"),
        "Dilithium2": ("drone\\drone_dilithium2.py", "gcs\\gcs_dilithium2.py"),
        "Dilithium3": ("drone\\drone_dilithium3.py", "gcs\\gcs_dilithium3.py"),
        "Falcon-512": ("drone\\drone_falcon512.py", "gcs\\gcs_falcon512.py"),
    }
    
    if algorithm_choice not in algorithms:
        print(f"Available algorithms: {list(algorithms.keys())}")
        print(f"Usage: python {sys.argv[0]} [algorithm_name]")
        return
    
    drone_script, gcs_script = algorithms[algorithm_choice]
    
    print(f"Quick Test: {algorithm_choice}")
    print(f"Drone: {drone_script}")
    print(f"GCS: {gcs_script}")
    print("=" * 50)
    
    # Clean up old logs
    for log_file in ["drone_app_log.txt", "gcs_app_log.txt"]:
        if os.path.exists(log_file):
            os.remove(log_file)
            print(f"Cleaned up {log_file}")
    
    processes = {}
    
    try:
        # Start dummy apps
        print("Starting dummy applications...")
        processes["drone_app"] = subprocess.Popen([sys.executable, "dummy_drone_app.py"])
        processes["gcs_app"] = subprocess.Popen([sys.executable, "dummy_gcs_app.py"])
        
        print("Waiting 5s for dummy apps to initialize...")
        time.sleep(5)
        
        # Start GCS proxy first
        print(f"Starting GCS proxy: {gcs_script}")
        processes["gcs_proxy"] = subprocess.Popen([sys.executable, gcs_script])
        
        time.sleep(3)
        
        # Start drone proxy
        print(f"Starting drone proxy: {drone_script}")  
        processes["drone_proxy"] = subprocess.Popen([sys.executable, drone_script])
        
        print("Waiting 5s for key exchange...")
        time.sleep(5)
        
        # Monitor for 20 seconds
        print("Monitoring communication for 20 seconds...")
        monitor_time = 20
        
        for i in range(monitor_time):
            time.sleep(1)
            if (i + 1) % 5 == 0:
                print(f"  {i+1}s elapsed...")
        
        print("\nAnalyzing results...")
        
        # Check logs
        drone_telemetry = 0
        drone_commands = 0
        gcs_commands = 0
        gcs_telemetry = 0
        
        if os.path.exists("drone_app_log.txt"):
            with open("drone_app_log.txt", "r") as f:
                content = f.read()
                drone_telemetry = content.count("SENT_TELEMETRY")
                drone_commands = content.count("RECEIVED_COMMAND")
        
        if os.path.exists("gcs_app_log.txt"):
            with open("gcs_app_log.txt", "r") as f:
                content = f.read()
                gcs_commands = content.count("SENT_COMMAND")
                gcs_telemetry = content.count("RECEIVED_TELEMETRY")
        
        print("\nCOMMUNICATION RESULTS:")
        print(f"Drone sent telemetry: {drone_telemetry}")
        print(f"GCS received telemetry: {gcs_telemetry}")
        print(f"GCS sent commands: {gcs_commands}")
        print(f"Drone received commands: {drone_commands}")
        
        success = (drone_telemetry > 0 and gcs_telemetry > 0 and 
                  gcs_commands > 0 and drone_commands > 0)
        
        if success:
            print(f"\n✅ {algorithm_choice} COMMUNICATION TEST PASSED!")
        else:
            print(f"\n❌ {algorithm_choice} COMMUNICATION TEST FAILED!")
        
    except Exception as e:
        print(f"Error: {e}")
    
    finally:
        print("\nCleaning up processes...")
        for name, process in processes.items():
            if process:
                try:
                    process.terminate()
                    process.wait(timeout=5)
                    print(f"Stopped {name}")
                except:
                    try:
                        process.kill()
                        print(f"Killed {name}")
                    except:
                        pass
    
    print("\nQuick test completed!")
    print("Check drone_app_log.txt and gcs_app_log.txt for detailed logs")

if __name__ == "__main__":
    main()