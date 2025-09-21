#!/usr/bin/env python3
"""
Unit tests for Dilithium (ML-DSA) implementations.
Tests key generation, signing, and verification operations.
"""

import pytest
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

class TestDilithiumMLDSA44:
    """Test ML-DSA-44 (Dilithium2) implementation."""
    
    def test_algorithm_disabled(self):
        """Test that insecure implementations are properly disabled."""
        with pytest.raises(NotImplementedError, match="liboqs-backed wrapper"):
            from drone.drone_dilithium2 import setup_dilithium_and_kyber
            setup_dilithium_and_kyber()
    
    def test_sign_verify_roundtrip(self):
        """Test key generation -> sign -> verify roundtrip."""
        pytest.skip("Requires secure liboqs wrapper implementation")
        
        # TODO: Implement when secure wrapper is available
        # sig = SecureDilithium44()
        # public_key = sig.generate_keypair()
        # message = b"test message"
        # signature = sig.sign(message)
        # assert sig.verify(message, signature, public_key) == True
        # assert len(public_key) == 1312
        # assert len(signature) <= 2420

class TestDilithiumMLDSA65:
    """Test ML-DSA-65 (Dilithium3) implementation."""
    
    def test_algorithm_disabled(self):
        """Test that insecure implementations are properly disabled."""
        with pytest.raises(NotImplementedError):
            from drone.drone_dilithium3 import setup_dilithium_and_kyber
            setup_dilithium_and_kyber()

class TestDilithiumMLDSA87:
    """Test ML-DSA-87 (Dilithium5) implementation."""
    
    def test_algorithm_disabled(self):
        """Test that insecure implementations are properly disabled."""
        with pytest.raises(NotImplementedError):
            from drone.drone_dilithium5 import setup_dilithium_and_kyber
            setup_dilithium_and_kyber()

# Known Answer Tests (KATs) - placeholder for liboqs integration
class TestDilithiumKATs:
    """Known Answer Tests using liboqs reference vectors."""
    
    @pytest.mark.skip(reason="Requires liboqs KAT vectors")
    def test_ml_dsa_44_kat_vectors(self):
        """Test ML-DSA-44 against known answer test vectors."""
        # TODO: Load KAT vectors from liboqs test data
        pass
    
    @pytest.mark.skip(reason="Requires liboqs KAT vectors")
    def test_ml_dsa_65_kat_vectors(self):
        """Test ML-DSA-65 against known answer test vectors."""
        pass
    
    @pytest.mark.skip(reason="Requires liboqs KAT vectors")
    def test_ml_dsa_87_kat_vectors(self):
        """Test ML-DSA-87 against known answer test vectors."""
        pass
