#!/bin/bash
# uninstall-linux.sh — Remove Linux capabilities and group setup for netoproc.
#
# Usage: sudo bash scripts/uninstall-linux.sh [path-to-netoproc]

set -euo pipefail

BINARY="${1:-$(command -v netoproc 2>/dev/null || echo "")}"
GROUP="netoproc"

if [ "$(id -u)" -ne 0 ]; then
    echo "error: this script must be run as root (sudo)"
    exit 1
fi

# 1. Remove capabilities from binary
if [ -n "$BINARY" ] && [ -f "$BINARY" ]; then
    setcap -r "$BINARY" 2>/dev/null || true
    chown root:root "$BINARY" 2>/dev/null || true
    chmod 755 "$BINARY" 2>/dev/null || true
    echo "Removed capabilities from $BINARY"
else
    echo "Binary not found, skipping capability removal"
fi

# 2. Remove group
if getent group "$GROUP" > /dev/null 2>&1; then
    groupdel "$GROUP"
    echo "Removed group: $GROUP"
else
    echo "Group $GROUP does not exist"
fi

echo "Done."
