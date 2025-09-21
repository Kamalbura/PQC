#!/usr/bin/env python3
"""
Unit tests for Kyber (ML-KEM) implementations.
Tests key generation, encapsulation, and decapsulation operations.
"""

import pytest
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

class TestKyberMLKEM512:
    """Test ML-KEM-512 implementation."""
    
    def test_algorithm_disabled(self):
        """Test that insecure implementations are properly disabled."""
        with pytest.raises(NotImplementedError, match="liboqs-backed wrapper"):
            from drone.drone_kyber_512 import setup_kyber
            setup_kyber()
    
    def test_key_generation_roundtrip(self):
        """Test key generation -> encapsulate -> decapsulate roundtrip."""
        pytest.skip("Requires secure liboqs wrapper implementation")
        
        # TODO: Implement when secure wrapper is available
        # kem = SecureKyber512()
        # public_key = kem.generate_keypair()
        # ciphertext, shared_secret1 = kem.encap_secret(public_key)
        # shared_secret2 = kem.decap_secret(ciphertext)
        # assert shared_secret1 == shared_secret2
        # assert len(public_key) == 800
        # assert len(shared_secret1) == 32

class TestKyberMLKEM768:
    """Test ML-KEM-768 implementation."""
    
    def test_algorithm_disabled(self):
        """Test that insecure implementations are properly disabled."""
        with pytest.raises(NotImplementedError):
            from drone.drone_kyber_768 import setup_kyber
            setup_kyber()

class TestKyberMLKEM1024:
    """Test ML-KEM-1024 implementation."""
    
    def test_algorithm_disabled(self):
        """Test that insecure implementations are properly disabled."""
        with pytest.raises(NotImplementedError):
            from drone.drone_kyber_1024 import setup_kyber
            setup_kyber()

# Known Answer Tests (KATs) - placeholder for liboqs integration
class TestKyberKATs:
    """Known Answer Tests using liboqs reference vectors."""
    
    @pytest.mark.skip(reason="Requires liboqs KAT vectors")
    def test_ml_kem_512_kat_vectors(self):
        """Test ML-KEM-512 against known answer test vectors."""
        # TODO: Load KAT vectors from liboqs test data
        pass
    
    @pytest.mark.skip(reason="Requires liboqs KAT vectors") 
    def test_ml_kem_768_kat_vectors(self):
        """Test ML-KEM-768 against known answer test vectors."""
        pass
    
    @pytest.mark.skip(reason="Requires liboqs KAT vectors")
    def test_ml_kem_1024_kat_vectors(self):
        """Test ML-KEM-1024 against known answer test vectors."""
        pass
