#!/bin/bash
# install-linux.sh — Set up Linux capabilities for running netoproc without sudo.
#
# Usage: sudo bash scripts/install-linux.sh [path-to-netoproc]
#
# What it does:
#   1. Creates a "netoproc" system group (if it doesn't exist)
#   2. Adds the current user to the group
#   3. Sets cap_net_raw,cap_net_admin,cap_sys_ptrace on the binary
#
# After running this script, log out and back in (or run `newgrp netoproc`)
# for group membership to take effect.

set -euo pipefail

BINARY="${1:-$(command -v netoproc 2>/dev/null || echo "")}"

if [ -z "$BINARY" ]; then
    echo "error: netoproc binary not found"
    echo "usage: sudo bash $0 [path-to-netoproc]"
    exit 1
fi

if [ ! -f "$BINARY" ]; then
    echo "error: $BINARY does not exist"
    exit 1
fi

if [ "$(id -u)" -ne 0 ]; then
    echo "error: this script must be run as root (sudo)"
    exit 1
fi

SUDO_USER="${SUDO_USER:-$USER}"
GROUP="netoproc"

# 1. Create group if needed
if ! getent group "$GROUP" > /dev/null 2>&1; then
    groupadd "$GROUP"
    echo "Created group: $GROUP"
else
    echo "Group already exists: $GROUP"
fi

# 2. Add user to group
if id -nG "$SUDO_USER" | grep -qw "$GROUP"; then
    echo "User $SUDO_USER is already in group $GROUP"
else
    usermod -aG "$GROUP" "$SUDO_USER"
    echo "Added user $SUDO_USER to group $GROUP"
fi

# 3. Set capabilities
setcap cap_net_raw,cap_net_admin,cap_sys_ptrace+eip "$BINARY"
echo "Set capabilities on $BINARY"

# 4. Set group ownership so only group members can execute
chgrp "$GROUP" "$BINARY"
chmod 750 "$BINARY"
echo "Set ownership to root:$GROUP with mode 750"

echo ""
echo "Done! Log out and back in (or run 'newgrp $GROUP') for group membership to take effect."
echo "Then run: netoproc"
