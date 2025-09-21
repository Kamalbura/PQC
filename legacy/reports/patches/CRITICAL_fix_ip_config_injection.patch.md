# Critical Security Patch: Fix Command Injection in IP Config

## Issue
The `update_hosts_persistent()` function uses unsafe regex replacement that could allow command injection attacks through malicious host parameters.

## Risk Level
**CRITICAL** - Remote code execution via configuration updates

## Patch Description
1. Adds input validation for host parameters using IP address and hostname validation
2. Replaces unsafe regex with safe string replacement
3. Implements atomic file writing to prevent corruption
4. Adds proper error handling and cleanup

## Testing
```bash
# Test valid inputs
python -c "from drone.ip_config import update_hosts_persistent; print(update_hosts_persistent('192.168.1.1', 'localhost'))"

# Test injection attempt (should raise ValueError)
python -c "from drone.ip_config import update_hosts_persistent; update_hosts_persistent('127.0.0.1\"; rm -rf /', None)"
```

## Security Benefits
- Prevents command injection attacks
- Validates all host inputs
- Atomic file operations prevent corruption
- Proper error handling and cleanup
