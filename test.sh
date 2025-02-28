#!/bin/bash

set -e
echo "Starting security tests..."

FAILED=0

### TEST 1: Attempt privilege escalation
echo "[TEST 1] Checking privilege escalation..."
su - secureuser -c "id" &>/dev/null && {
    echo "[FAIL] Secure user was able to use 'su'!"
    FAILED=1
} || echo "[PASS] Secure user cannot use 'su'"

### TEST 2: Attempt modifying /etc/passwd (should fail)
echo "[TEST 2] Checking write protection for /etc/passwd..."
echo "test:x:1001:1001::/home/test:/bin/bash" >> /etc/passwd 2>/dev/null && {
    echo "[FAIL] Was able to modify /etc/passwd!"
    FAILED=1
} || echo "[PASS] /etc/passwd is protected"

### TEST 3: Attempt modifying /etc/shadow (should fail)
echo "[TEST 3] Checking write protection for /etc/shadow..."
echo "root:*:12345:0:99999:7:::" >> /etc/shadow 2>/dev/null && {
    echo "[FAIL] Was able to modify /etc/shadow!"
    FAILED=1
} || echo "[PASS] /etc/shadow is protected"

### TEST 4: Attempt to execute in /tmp (should fail if mounted with noexec)
echo "[TEST 4] Checking execution in /tmp..."
echo "echo HACKED" > /tmp/malicious.sh
chmod +x /tmp/malicious.sh
/tmp/malicious.sh &>/dev/null && {
    echo "[FAIL] Was able to execute in /tmp!"
    FAILED=1
} || echo "[PASS] Execution in /tmp is restricted"

### TEST 5: Attempt SSH root login (should fail)
echo "[TEST 5] Checking SSH root login..."
ssh -o BatchMode=yes root@localhost "echo FAIL" 2>/dev/null && {
    echo "[FAIL] Root was able to log in via SSH!"
    FAILED=1
} || echo "[PASS] Root login via SSH is disabled"

### TEST 6: Simulate brute force attack on SSH (fail2ban should block)
echo "[TEST 6] Simulating SSH brute force attack..."
for i in {1..5}; do
    ssh -o BatchMode=yes baduser@localhost "exit" 2>/dev/null
done

IP_BLOCKED=$(iptables -L | grep "REJECT" | grep "fail2ban")
if [[ -n "$IP_BLOCKED" ]]; then
    echo "[PASS] Fail2Ban is blocking brute force attempts"
else
    echo "[FAIL] Fail2Ban is NOT blocking brute force attempts!"
    FAILED=1
fi

### TEST 7: Attempt to load blacklisted USB storage module
echo "[TEST 7] Checking USB storage module loading..."
modprobe usb-storage &>/dev/null && {
    echo "[FAIL] USB storage module was loaded!"
    FAILED=1
} || echo "[PASS] USB storage module is blocked"

### TEST 8: Attempt to load blacklisted FireWire module
echo "[TEST 8] Checking FireWire module loading..."
modprobe firewire-core &>/dev/null && {
    echo "[FAIL] FireWire module was loaded!"
    FAILED=1
} || echo "[PASS] FireWire module is blocked"

### TEST 9: Attempt unauthorized access to /root
echo "[TEST 9] Checking access to /root..."
su - secureuser -c "ls /root" &>/dev/null && {
    echo "[FAIL] Secure user can access /root!"
    FAILED=1
} || echo "[PASS] /root is restricted"

### TEST 10: Check auditd logging
echo "[TEST 10] Checking audit logs..."
auditctl -l | grep "/etc/passwd" &>/dev/null && {
    echo "[PASS] Audit logs are tracking /etc/passwd changes"
} || {
    echo "[FAIL] Audit logs are NOT tracking /etc/passwd!"
    FAILED=1
}

### TEST 11: Try creating a suid binary in /tmp (should fail)
echo "[TEST 11] Checking SUID binary creation in /tmp..."
echo -e "#!/bin/bash\necho HACKED" > /tmp/suid_bin
chmod 4777 /tmp/suid_bin
/tmp/suid_bin &>/dev/null && {
    echo "[FAIL] Was able to execute SUID binary!"
    FAILED=1
} || echo "[PASS] SUID execution is restricted"

# Test Summary
if [[ "$FAILED" -eq 1 ]]; then
    echo "❌ Some tests failed. Review your security configuration."
else
    echo "✅ All tests passed! Your container is locked down."
fi
