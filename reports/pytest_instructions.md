# pytest Instructions for PQC Framework Testing

## Environment Setup

### Required Dependencies
```bash
pip install pytest pytest-cov pytest-mock
```

### Optional Environment Variables
```bash
# Path to local liboqs source (for KAT vectors)
export LIBOQS_SOURCE_PATH=/path/to/liboqs

# Enable verbose test output
export PYTEST_VERBOSE=1

# Skip slow integration tests
export PYTEST_SKIP_INTEGRATION=1
```

## Running Tests

### All Tests
```bash
# From repository root
python -m pytest reports/tests/ -v

# With coverage
python -m pytest reports/tests/ --cov=drone --cov=gcs --cov-report=html
```

### Specific Test Categories
```bash
# PQC algorithm tests only
python -m pytest reports/tests/pqc/ -v

# Integration tests only  
python -m pytest reports/tests/integration/ -v

# Test specific algorithm
python -m pytest reports/tests/pqc/test_kyber.py -v
```

### Test Markers
```bash
# Skip tests requiring liboqs KAT vectors
python -m pytest -m "not kat_vectors"

# Run only security tests
python -m pytest -m "security"

# Skip disabled implementations
python -m pytest -m "not disabled"
```

## Current Test Status

### Expected Behavior (Post-Patches)
All current algorithm implementations should raise `NotImplementedError` when imported or initialized, indicating they are properly disabled due to security issues.

### Test Results Before Patches Applied
```bash
# These should FAIL (indicating insecure implementations are active)
python -m pytest reports/tests/pqc/test_kyber.py::TestKyberMLKEM512::test_algorithm_disabled

# Expected output:
# FAILED - No NotImplementedError raised (SECURITY RISK)
```

### Test Results After Patches Applied
```bash
# These should PASS (indicating implementations are properly disabled)
python -m pytest reports/tests/pqc/test_kyber.py::TestKyberMLKEM512::test_algorithm_disabled

# Expected output:
# PASSED - NotImplementedError correctly raised
```

## Integration with liboqs KAT Vectors

### If liboqs source is available
```bash
# Set environment variable
export LIBOQS_SOURCE_PATH=/path/to/crypto/liboqs-python

# Run KAT tests (currently skipped)
python -m pytest reports/tests/pqc/ -k "kat_vectors" --run-kat
```

### KAT Vector Locations
- ML-KEM: `liboqs-python/tests/test_kem.py`
- ML-DSA: `liboqs-python/tests/test_sig.py`
- Falcon: `liboqs-python/tests/test_sig.py`
- SPHINCS+: `liboqs-python/tests/test_sig.py`

## Security Test Validation

### Critical Security Checks
```bash
# Verify no global key storage
python -c "
import sys; sys.path.append('.')
try:
    from drone.drone_kyber_512 import *
    print('FAIL: Should raise NotImplementedError')
except NotImplementedError:
    print('PASS: Properly disabled')
"

# Verify IP config injection protection  
python -c "
from drone.ip_config import update_hosts_persistent
try:
    update_hosts_persistent('127.0.0.1\"; rm -rf /', None)
    print('FAIL: Injection not prevented')
except ValueError:
    print('PASS: Injection prevented')
"
```

## Continuous Integration

### GitHub Actions Workflow
```yaml
name: Security Tests
on: [push, pull_request]
jobs:
  security-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.9'
      - name: Install dependencies
        run: |
          pip install pytest pytest-cov bandit
      - name: Run security tests
        run: |
          python -m pytest reports/tests/ -v
          bandit -r drone/ gcs/ -f json -o security-report.json
```

## Test Development Guidelines

### Adding New Tests
1. Place algorithm tests in `reports/tests/pqc/`
2. Place integration tests in `reports/tests/integration/`
3. Use descriptive test names with security implications
4. Always test both success and failure cases
5. Include tests for injection/overflow vulnerabilities

### Test Naming Convention
- `test_algorithm_disabled()` - Verify insecure implementations are disabled
- `test_*_injection_protection()` - Verify input validation
- `test_*_bounds_checking()` - Verify buffer overflow protection
- `test_*_kat_vectors()` - Known Answer Tests with liboqs vectors
