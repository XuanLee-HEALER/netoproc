#!/bin/bash
set -euo pipefail

PLIST_LABEL="org.netoproc.bpf"
PLIST_PATH="/Library/LaunchDaemons/${PLIST_LABEL}.plist"
GROUP_NAME="access_bpf"
CURRENT_USER="$(whoami)"

info()    { echo "[INFO]  $*"; }
success() { echo "[OK]    $*"; }
warn()    { echo "[WARN]  $*"; }
error()   { echo "[ERROR] $*" >&2; exit 1; }

# Check root
if [ "$(id -u)" -ne 0 ]; then
    error "This script must be run with sudo: sudo bash scripts/install-bpf.sh"
fi

# Get the actual invoking user (SUDO_USER is the original user under sudo)
TARGET_USER="${SUDO_USER:-$CURRENT_USER}"

info "Installing netoproc BPF permission configuration..."

# Step 1: Create access_bpf group (idempotent)
if dseditgroup -o read "$GROUP_NAME" &>/dev/null; then
    info "Group '$GROUP_NAME' already exists, skipping creation."
else
    dseditgroup -o create -q "$GROUP_NAME"
    success "Created group '$GROUP_NAME'."
fi

# Step 2: Add target user to group (idempotent)
if dseditgroup -o checkmember -m "$TARGET_USER" "$GROUP_NAME" &>/dev/null; then
    info "User '$TARGET_USER' is already in group '$GROUP_NAME', skipping."
else
    dseditgroup -o edit -a "$TARGET_USER" -t user "$GROUP_NAME"
    success "Added user '$TARGET_USER' to group '$GROUP_NAME'."
fi

# Step 3: Write launchd plist
cat > "$PLIST_PATH" << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
    "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>org.netoproc.bpf</string>
    <key>ProgramArguments</key>
    <array>
        <string>/bin/sh</string>
        <string>-c</string>
        <string>chgrp access_bpf /dev/bpf* &amp;&amp; chmod g+rw /dev/bpf*</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>LaunchOnlyOnce</key>
    <true/>
</dict>
</plist>
EOF

# Set plist permissions (must be root:wheel 644, or launchd refuses to load)
chown root:wheel "$PLIST_PATH"
chmod 644 "$PLIST_PATH"
success "Installed launchd plist at $PLIST_PATH."

# Step 4: Load plist and execute immediately (no reboot needed)
if launchctl list | grep -q "$PLIST_LABEL"; then
    launchctl unload "$PLIST_PATH"
fi
launchctl load "$PLIST_PATH"
launchctl start "$PLIST_LABEL"
success "BPF device permissions updated immediately."

# Verify
if ls -la /dev/bpf0 2>/dev/null | grep -q "access_bpf"; then
    success "Verified: /dev/bpf* is now accessible by group '$GROUP_NAME'."
else
    warn "Could not verify /dev/bpf permissions. Please reboot if netoproc fails to run."
fi

echo ""
echo "Installation complete."
echo ""
echo "IMPORTANT: You need to log out and log back in for group membership"
echo "to take effect in your current shell session."
echo ""
echo "After re-login, run netoproc without sudo:"
echo "  netoproc"
