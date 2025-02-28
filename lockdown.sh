#!/bin/bash

set -e

echo "Starting container security lockdown..."

# Ensure SELinux is enforcing
if command -v setenforce &>/dev/null; then
    echo "Setting SELinux to enforcing mode..."
    setenforce 1
fi

# Update system packages
echo "Updating system packages..."
if command -v apt-get &>/dev/null; then
    apt-get update && apt-get upgrade -y
elif command -v yum &>/dev/null; then
    yum update -y
elif command -v dnf &>/dev/null; then
    dnf update -y
elif command -v zypper &>/dev/null; then
    zypper update -y
else
    echo "Unknown package manager! Update manually."
fi

# Install fail2ban, auditd, and process accounting tools
echo "Installing fail2ban, auditd, and process accounting..."
if command -v apt-get &>/dev/null; then
    apt-get install -y fail2ban auditd acct
elif command -v yum &>/dev/null; then
    yum install -y fail2ban audit audit-libs acct
elif command -v dnf &>/dev/null; then
    dnf install -y fail2ban audit audit-libs acct
elif command -v zypper &>/dev/null; then
    zypper install -y fail2ban audit audit-libs acct
fi

# Start and enable services
echo "Enabling and starting services..."
systemctl enable --now fail2ban auditd

# Enable process accounting
echo "Enabling process accounting..."
accton on

# Restrict login access
echo "Restricting login access..."
echo "ALL: ALL" >> /etc/hosts.deny

# Create a low-privilege user
echo "Creating low-privilege user..."
useradd -m -s /usr/sbin/nologin secureuser

# Restrict access to /root and other sensitive folders
echo "Restricting /root access..."
chmod 700 /root
chmod 750 /home

# Disable FireWire and USB storage
echo "Disabling FireWire and USB storage..."
echo "blacklist firewire-core" >> /etc/modprobe.d/blacklist.conf
echo "blacklist usb-storage" >> /etc/modprobe.d/blacklist.conf
echo "install usb-storage /bin/false" >> /etc/modprobe.d/usb-storage.conf

# Ensure modules are not loaded
modprobe -r firewire-core || true
modprobe -r usb-storage || true

# Move /tmp to tmpfs
echo "Mounting /tmp as tmpfs..."
echo "tmpfs /tmp tmpfs defaults,noexec,nosuid,nodev 0 0" >> /etc/fstab
mount -o remount /tmp

# Disable root login and restrict SSH
echo "Disabling root login and enforcing SSH security..."
if [[ -f /etc/ssh/sshd_config ]]; then
    sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
    sed -i 's/^PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
    systemctl restart sshd
fi

# Enable auditing rules
echo "Applying audit rules..."
cat <<EOF > /etc/audit/rules.d/hardening.rules
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /var/log/ -p wa -k log_changes
EOF
augenrules --load
systemctl restart auditd

echo "Container lockdown completed!"
