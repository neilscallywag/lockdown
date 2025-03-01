# lockdown
Based on [lockdown.sh](https://github.com/dolegi/lockdown.sh)
- ✅ Enables SELinux in enforcing mode
- ✅ Updates and patches system packages
- ✅ Installs fail2ban, auditd, and enables process accounting
- ✅ Blocks all external login attempts
- ✅ Creates a non-root user for better security
- ✅ Restricts access to /root and /home
- ✅ Disables USB storage and FireWire to prevent data leaks
- ✅ Moves /tmp to tmpfs for better security
- ✅ Locks down SSH (disables root login, enforces key-based auth)
- ✅ Configures audit rules for tracking system changes
