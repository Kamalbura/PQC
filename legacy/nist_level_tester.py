#!/usr/bin/env python3
"""
NIST Security Level Testing Framework
Test PQC algorithms organized by NIST security levels

This script provides organized testing by security level:
- Level 1 (128-bit): Basic security, fastest performance
- Level 3 (192-bit): Strong security, balanced performance  
- Level 5 (256-bit): Maximum security, highest computational cost

Usage: python nist_level_tester.py [level] [algorithm]
Examples:
  python nist_level_tester.py 1             # Test all Level 1 algorithms
  python nist_level_tester.py 3 ML-KEM-768  # Test specific Level 3 algorithm
  python nist_level_tester.py all           # Test all levels sequentially
"""

import subprocess
import time
import sys
import os
from datetime import datetime

# NIST Security Level Algorithm Mapping
NIST_LEVELS = {
    1: {
        "description": "NIST Level 1 (128-bit) - Basic security, fastest performance",
        "equivalent": "AES-128",
        "path": "level1_128bit",
        "algorithms": {
            "ML-KEM-512": ("drone_kyber_512.py", "gcs_kyber_512.py"),
            "ML-DSA-44": ("drone_dilithium2.py", "gcs_dilithium2.py"),
            "Falcon-512": ("drone_falcon512.py", "gcs_falcon512.py"),
            "SPHINCS+-SHA2-128f": ("drone_sphincs_sha2_128f.py", "gcs_sphincs_sha2_128f.py"),
            "SPHINCS+-Haraka-128f": ("drone_sphincs_haraka_128f.py", "gcs_sphincs_haraka_128f.py")
        }
    },
    3: {
        "description": "NIST Level 3 (192-bit) - Strong security, balanced performance",
        "equivalent": "AES-192",
        "path": "level3_192bit",
        "algorithms": {
            "ML-KEM-768": ("drone_kyber_768.py", "gcs_kyber_768.py"),
            "ML-DSA-65": ("drone_dilithium3.py", "gcs_dilithium3.py")
        }
    },
    5: {
        "description": "NIST Level 5 (256-bit) - Maximum security, highest computational cost",
        "equivalent": "AES-256",
        "path": "level5_256bit",
        "algorithms": {
            "ML-KEM-1024": ("drone_kyber_1024.py", "gcs_kyber_1024.py"),
            "ML-DSA-87": ("drone_dilithium5.py", "gcs_dilithium5.py"),
            "Falcon-1024": ("drone_falcon1024.py", "gcs_falcon1024.py"),
            "SPHINCS+-SHA2-256f": ("drone_sphincs_sha2_256f.py", "gcs_sphincs_sha2_256f.py"),
            "SPHINCS+-Haraka-256f": ("drone_sphincs_haraka_256f.py", "gcs_sphincs_haraka_256f.py")
        }
    }
}

def print_banner():
    print("=" * 70)
    print("🔐 NIST SECURITY LEVEL TESTING FRAMEWORK")
    print("=" * 70)
    print("Post-Quantum Cryptography Algorithm Testing by Security Level")
    print()

def print_level_info(level):
    """Print information about a specific NIST level"""
    if level in NIST_LEVELS:
        info = NIST_LEVELS[level]
        print(f"📊 {info['description']}")
        print(f"   Equivalent to: {info['equivalent']}")
        print(f"   Algorithms: {len(info['algorithms'])}")
        for algo_name in info['algorithms']:
            print(f"     • {algo_name}")
        print()

def cleanup_logs():
    """Remove old log files"""
    log_files = ["drone_app_log.txt", "gcs_app_log.txt"]
    cleaned = 0
    for log_file in log_files:
        if os.path.exists(log_file):
            os.remove(log_file)
            cleaned += 1
    if cleaned > 0:
        print(f"🧹 Cleaned up {cleaned} old log files")

def test_algorithm(level, algorithm_name, drone_script, gcs_script):
    """Test a single algorithm"""
    level_path = NIST_LEVELS[level]["path"]
    
    print(f"\n🧪 Testing {algorithm_name} (Level {level})")
    print("-" * 50)
    
    processes = {}
    success = False
    
    try:
        # Start dummy applications
        print("1️⃣  Starting dummy applications...")
        processes["drone_app"] = subprocess.Popen([sys.executable, "interactive_drone_app.py"])
        processes["gcs_app"] = subprocess.Popen([sys.executable, "interactive_gcs_app.py"])
        time.sleep(3)
        
        # Start GCS proxy
        gcs_path = f"{level_path}\\gcs\\{gcs_script}"
        print(f"2️⃣  Starting GCS proxy: {gcs_path}")
        processes["gcs_proxy"] = subprocess.Popen([sys.executable, gcs_path])
        time.sleep(2)
        
        # Start Drone proxy
        drone_path = f"{level_path}\\drone\\{drone_script}"
        print(f"3️⃣  Starting drone proxy: {drone_path}")
        processes["drone_proxy"] = subprocess.Popen([sys.executable, drone_path])
        time.sleep(3)
        
        print("4️⃣  Monitoring communication...")
        
        # Monitor for algorithm readiness
        monitor_time = 15
        for i in range(monitor_time):
            time.sleep(1)
            if (i + 1) % 5 == 0:
                print(f"   {i+1}s elapsed...")
        
        # Check if proxies are still running (indication of success)
        gcs_running = processes["gcs_proxy"].poll() is None
        drone_running = processes["drone_proxy"].poll() is None
        
        if gcs_running and drone_running:
            print(f"✅ {algorithm_name} proxies started successfully!")
            print("   Note: Use interactive apps to test communication manually")
            success = True
        else:
            print(f"❌ {algorithm_name} failed to start properly")
            
    except Exception as e:
        print(f"❌ Error testing {algorithm_name}: {e}")
    
    finally:
        # Clean up processes
        print("5️⃣  Cleaning up...")
        for name, process in processes.items():
            try:
                process.terminate()
                process.wait(timeout=3)
            except:
                try:
                    process.kill()
                except:
                    pass
        time.sleep(1)
    
    return success

def test_level(level):
    """Test all algorithms in a specific NIST level"""
    if level not in NIST_LEVELS:
        print(f"❌ Invalid NIST level: {level}")
        return False
    
    print_level_info(level)
    
    level_info = NIST_LEVELS[level]
    results = {}
    
    for algo_name, (drone_script, gcs_script) in level_info["algorithms"].items():
        cleanup_logs()
        result = test_algorithm(level, algo_name, drone_script, gcs_script)
        results[algo_name] = result
        time.sleep(2)  # Brief pause between algorithms
    
    # Summary for this level
    print(f"\n📈 LEVEL {level} RESULTS SUMMARY:")
    print("=" * 40)
    successful = sum(results.values())
    total = len(results)
    
    for algo_name, success in results.items():
        status = "✅ PASS" if success else "❌ FAIL"
        print(f"  {algo_name:<25} {status}")
    
    print(f"\nLevel {level} Success Rate: {successful}/{total} ({100*successful//total if total > 0 else 0}%)")
    return results

def interactive_selection():
    """Interactive level and algorithm selection"""
    print("📋 Available NIST Security Levels:")
    print("-" * 35)
    for level, info in NIST_LEVELS.items():
        print(f"Level {level}: {info['equivalent']} equivalent ({len(info['algorithms'])} algorithms)")
    print("All: Test all levels sequentially")
    print()
    
    while True:
        try:
            choice = input("Select level (1/3/5/all): ").strip().lower()
            
            if choice == "all":
                return "all", None
            elif choice in ["1", "3", "5"]:
                level = int(choice)
                
                # Show algorithms for this level
                algorithms = list(NIST_LEVELS[level]["algorithms"].keys())
                print(f"\nAlgorithms in Level {level}:")
                for i, algo in enumerate(algorithms, 1):
                    print(f"  {i}. {algo}")
                print("  all. Test all algorithms in this level")
                
                algo_choice = input(f"Select algorithm (1-{len(algorithms)}/all): ").strip().lower()
                
                if algo_choice == "all":
                    return level, None
                elif algo_choice.isdigit():
                    idx = int(algo_choice) - 1
                    if 0 <= idx < len(algorithms):
                        return level, algorithms[idx]
                
                print("❌ Invalid algorithm selection")
            else:
                print("❌ Invalid level selection")
                
        except (KeyboardInterrupt, EOFError):
            print("\n👋 Goodbye!")
            sys.exit(0)

def main():
    print_banner()
    
    # Parse command line arguments
    if len(sys.argv) > 1:
        arg1 = sys.argv[1].lower()
        
        if arg1 == "all":
            # Test all levels
            print("🚀 Testing ALL NIST security levels...")
            all_results = {}
            
            for level in sorted(NIST_LEVELS.keys()):
                print(f"\n{'='*50}")
                print(f"STARTING NIST LEVEL {level} TESTING")
                print(f"{'='*50}")
                all_results[level] = test_level(level)
            
            # Overall summary
            print(f"\n{'='*70}")
            print("📊 FINAL RESULTS SUMMARY")
            print(f"{'='*70}")
            
            for level, results in all_results.items():
                successful = sum(results.values())
                total = len(results)
                print(f"Level {level}: {successful}/{total} algorithms passed")
            
            return
            
        elif arg1 in ["1", "3", "5"]:
            level = int(arg1)
            
            if len(sys.argv) > 2:
                # Specific algorithm
                algorithm = sys.argv[2]
                if algorithm in NIST_LEVELS[level]["algorithms"]:
                    drone_script, gcs_script = NIST_LEVELS[level]["algorithms"][algorithm]
                    cleanup_logs()
                    test_algorithm(level, algorithm, drone_script, gcs_script)
                else:
                    print(f"❌ Algorithm '{algorithm}' not found in Level {level}")
                    print(f"Available: {list(NIST_LEVELS[level]['algorithms'].keys())}")
            else:
                # All algorithms in level
                test_level(level)
            return
    
    # Interactive mode
    level_choice, algo_choice = interactive_selection()
    
    if level_choice == "all":
        # Test all levels
        for level in sorted(NIST_LEVELS.keys()):
            test_level(level)
    elif algo_choice is None:
        # Test all algorithms in level
        test_level(level_choice)
    else:
        # Test specific algorithm
        drone_script, gcs_script = NIST_LEVELS[level_choice]["algorithms"][algo_choice]
        cleanup_logs()
        test_algorithm(level_choice, algo_choice, drone_script, gcs_script)

if __name__ == "__main__":
    main()