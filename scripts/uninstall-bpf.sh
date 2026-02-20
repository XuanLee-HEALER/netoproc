#!/bin/bash
set -euo pipefail

PLIST_LABEL="org.netoproc.bpf"
PLIST_PATH="/Library/LaunchDaemons/${PLIST_LABEL}.plist"
GROUP_NAME="access_bpf"

info()    { echo "[INFO]  $*"; }
success() { echo "[OK]    $*"; }
error()   { echo "[ERROR] $*" >&2; exit 1; }

if [ "$(id -u)" -ne 0 ]; then
    error "This script must be run with sudo: sudo bash scripts/uninstall-bpf.sh"
fi

info "Uninstalling netoproc BPF permission configuration..."

# Unload and remove plist
if launchctl list | grep -q "$PLIST_LABEL"; then
    launchctl unload "$PLIST_PATH"
    success "Unloaded launchd service."
fi

if [ -f "$PLIST_PATH" ]; then
    rm "$PLIST_PATH"
    success "Removed plist at $PLIST_PATH."
fi

# Delete group (automatically removes all members)
if dseditgroup -o read "$GROUP_NAME" &>/dev/null; then
    dseditgroup -o delete "$GROUP_NAME"
    success "Deleted group '$GROUP_NAME'."
fi

# Restore bpf device permissions to system defaults
chgrp wheel /dev/bpf* 2>/dev/null && chmod g-rw /dev/bpf* 2>/dev/null || true
success "Restored /dev/bpf* permissions to default."

echo ""
echo "Uninstallation complete."
