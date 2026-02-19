# netoproc macOS 权限管理设计文档

> 本文档描述 netoproc 在 macOS 上的权限管理方案，供实现安装脚本和 Homebrew formula 使用。

---

## 1. 问题背景

netoproc 通过 BPF（Berkeley Packet Filter）抓取网络数据包，macOS 上 BPF 设备文件位于 `/dev/bpf0`、`/dev/bpf1`……默认权限为：

```
crw-------  root  wheel  /dev/bpf*
```

普通用户无法打开这些设备，必须以 root 身份运行或通过权限管理授权。

---

## 2. 解决方案

### 2.1 核心思路

在系统中创建 `access_bpf` 用户组，通过 launchd 在系统启动时将 `/dev/bpf*` 的组所有权修改为 `access_bpf` 并赋予组读写权限。用户只需在安装时加入该组，此后无需 sudo 即可运行 netoproc。

权限变更后 bpf 设备的状态：

```
crw-rw----  root  access_bpf  /dev/bpf*
```

### 2.2 为什么选择这个方案

- **运行时零开销**：权限在系统启动时一次性配置，工具运行期间不涉及任何权限切换
- **概念模型干净**：权限问题完全收敛在用户组域内，工具代码本身无需感知权限逻辑
- **与 Linux 同构**：Linux 上同样通过用户组（配合 udev rules 或 capabilities）控制抓包权限，用户心智模型一致
- **符合 macOS 惯例**：与 Wireshark 在 macOS 上的权限方案相同，用户有已知参照

---

## 3. 实现细节

### 3.1 涉及的系统机制

**dseditgroup**：macOS 的目录服务命令行工具，用于管理本地用户组。

**launchd**：macOS 的服务管理框架，通过 plist 文件描述在特定时机执行的任务。LaunchDaemons（`/Library/LaunchDaemons/`）在系统启动时以 root 身份运行，早于用户登录，适合修改设备文件权限。

**bpf 设备数量**：macOS 动态创建 bpf 设备，数量由内核决定，通常为 bpf0 到 bpf255。使用通配符 `/dev/bpf*` 覆盖全部设备。

### 3.2 launchd plist

文件路径：`/Library/LaunchDaemons/org.netoproc.bpf.plist`

```xml
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

    <!-- 系统启动时自动执行 -->
    <key>RunAtLoad</key>
    <true/>

    <!-- 只执行一次，不持续运行 -->
    <key>LaunchOnlyOnce</key>
    <true/>
</dict>
</plist>
```

**关键字段说明**：

- `RunAtLoad`：launchd 加载此 plist 时立即执行，即系统每次启动时自动执行
- `LaunchOnlyOnce`：任务执行完毕后不再重启，适合一次性的配置任务
- `ProgramArguments` 使用 `/bin/sh -c` 是为了支持通配符 `/dev/bpf*`，直接调用 `chgrp` 无法展开通配符

### 3.3 执行顺序

系统启动时的执行链：

```
系统内核启动
    ↓
launchd 启动，加载 /Library/LaunchDaemons/ 下所有 plist
    ↓
执行 org.netoproc.bpf：chgrp access_bpf /dev/bpf* && chmod g+rw /dev/bpf*
    ↓
/dev/bpf* 权限变更为 crw-rw----  root  access_bpf
    ↓
用户登录，access_bpf 组成员可直接运行 netoproc
```

---

## 4. 安装脚本

### 4.1 脚本职责

安装脚本（`install.sh`）需要完成以下操作：

1. 创建 `access_bpf` 用户组（幂等，已存在则跳过）
2. 将当前用户加入 `access_bpf` 组
3. 将 launchd plist 写入 `/Library/LaunchDaemons/`
4. 加载并立即执行 plist（无需重启即生效）

### 4.2 install.sh 完整实现

```bash
#!/bin/bash
set -euo pipefail

PLIST_LABEL="org.netoproc.bpf"
PLIST_PATH="/Library/LaunchDaemons/${PLIST_LABEL}.plist"
GROUP_NAME="access_bpf"
CURRENT_USER="$(whoami)"

# 颜色输出
info()    { echo "[INFO]  $*"; }
success() { echo "[OK]    $*"; }
warn()    { echo "[WARN]  $*"; }
error()   { echo "[ERROR] $*" >&2; exit 1; }

# 检查是否以 root 运行
if [ "$(id -u)" -ne 0 ]; then
    error "This script must be run with sudo: sudo bash install.sh"
fi

# 获取实际调用者（sudo 场景下 SUDO_USER 是原始用户名）
TARGET_USER="${SUDO_USER:-$CURRENT_USER}"

info "Installing netoproc BPF permission configuration..."

# Step 1: 创建 access_bpf 用户组（幂等）
if dseditgroup -o read "$GROUP_NAME" &>/dev/null; then
    info "Group '$GROUP_NAME' already exists, skipping creation."
else
    dseditgroup -o create -q "$GROUP_NAME"
    success "Created group '$GROUP_NAME'."
fi

# Step 2: 将目标用户加入组（幂等）
if dseditgroup -o checkmember -m "$TARGET_USER" "$GROUP_NAME" &>/dev/null; then
    info "User '$TARGET_USER' is already in group '$GROUP_NAME', skipping."
else
    dseditgroup -o edit -a "$TARGET_USER" -t user "$GROUP_NAME"
    success "Added user '$TARGET_USER' to group '$GROUP_NAME'."
fi

# Step 3: 写入 launchd plist
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

# 设置 plist 文件权限（必须为 root:wheel 644，否则 launchd 拒绝加载）
chown root:wheel "$PLIST_PATH"
chmod 644 "$PLIST_PATH"
success "Installed launchd plist at $PLIST_PATH."

# Step 4: 加载 plist 并立即执行（使当前会话即时生效，无需重启）
# 如果已加载，先卸载再重新加载
if launchctl list | grep -q "$PLIST_LABEL"; then
    launchctl unload "$PLIST_PATH"
fi
launchctl load "$PLIST_PATH"
launchctl start "$PLIST_LABEL"
success "BPF device permissions updated immediately."

# 验证结果
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
```

### 4.3 卸载脚本（uninstall.sh）

```bash
#!/bin/bash
set -euo pipefail

PLIST_LABEL="org.netoproc.bpf"
PLIST_PATH="/Library/LaunchDaemons/${PLIST_LABEL}.plist"
GROUP_NAME="access_bpf"

info()    { echo "[INFO]  $*"; }
success() { echo "[OK]    $*"; }
error()   { echo "[ERROR] $*" >&2; exit 1; }

if [ "$(id -u)" -ne 0 ]; then
    error "This script must be run with sudo: sudo bash uninstall.sh"
fi

info "Uninstalling netoproc BPF permission configuration..."

# 卸载并移除 plist
if launchctl list | grep -q "$PLIST_LABEL"; then
    launchctl unload "$PLIST_PATH"
    success "Unloaded launchd service."
fi

if [ -f "$PLIST_PATH" ]; then
    rm "$PLIST_PATH"
    success "Removed plist at $PLIST_PATH."
fi

# 删除用户组（这会自动将所有成员移出该组）
if dseditgroup -o read "$GROUP_NAME" &>/dev/null; then
    dseditgroup -o delete "$GROUP_NAME"
    success "Deleted group '$GROUP_NAME'."
fi

# 恢复 bpf 设备权限为系统默认
chgrp wheel /dev/bpf* 2>/dev/null && chmod g-rw /dev/bpf* 2>/dev/null || true
success "Restored /dev/bpf* permissions to default."

echo ""
echo "Uninstallation complete."
```

---

## 5. Homebrew Formula 集成

Homebrew 安装时需要在 `post_install` 中执行权限配置，并在 `caveats` 中告知用户后续步骤。

### 5.1 关键实现

```ruby
def post_install
  # 创建 access_bpf 组
  system "dseditgroup", "-o", "create", "-q", "access_bpf"

  # 安装 launchd plist
  plist_path = "/Library/LaunchDaemons/org.netoproc.bpf.plist"
  plist_content = <<~EOS
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
  EOS

  File.write(plist_path, plist_content)
  system "chown", "root:wheel", plist_path
  system "chmod", "644", plist_path
  system "launchctl", "load", plist_path
  system "launchctl", "start", "org.netoproc.bpf"
end

def caveats
  <<~EOS
    To run netoproc without sudo, add yourself to the access_bpf group:

      sudo dseditgroup -o edit -a $(whoami) -t user access_bpf

    Then log out and back in for the group membership to take effect.

    To uninstall the BPF permission configuration:

      sudo bash #{HOMEBREW_PREFIX}/share/netoproc/uninstall.sh
  EOS
end
```

### 5.2 Homebrew 与独立脚本的分工

Homebrew `post_install` 只负责系统级配置（创建组、安装 plist），**不**自动将用户加入组，原因是 `post_install` 以 root 身份运行，`SUDO_USER` 在 Homebrew 环境中不可靠。将用户加组的步骤留给用户按 `caveats` 提示手动执行，这是 Homebrew formula 的惯例做法。

独立安装脚本（GitHub Release 分发）则通过 `SUDO_USER` 自动完成加组，提供更完整的一键安装体验。

---

## 6. 注意事项

### 6.1 组成员变更需要重新登录

将用户加入 `access_bpf` 组后，当前 shell session 的组信息不会立即更新，必须重新登录（或新开终端会话）才能生效。这是 macOS/Unix 用户组机制的固有行为，安装脚本末尾需要明确提示用户。

可以用以下命令验证当前 session 是否已包含该组：

```bash
groups | grep access_bpf
```

### 6.2 plist 文件权限要求

launchd 对 LaunchDaemons 目录下的 plist 文件有严格要求：

- 所有者必须是 `root:wheel`
- 权限必须是 `644`（不能有 group/other 写权限）
- 否则 launchd 会拒绝加载并报 `Operation not permitted`

安装脚本中的 `chown root:wheel` 和 `chmod 644` 是必须步骤，不可省略。

### 6.3 重启后的持久性

launchd plist 设置了 `RunAtLoad`，系统每次重启时会重新执行权限修改命令。由于 macOS 在重启后会重置 `/dev/bpf*` 的权限为默认值，这一步是保证持久性的关键。

### 6.4 macOS 版本兼容性

`dseditgroup` 和 launchd 在 macOS 10.15（Catalina）及以上版本行为一致。不需要针对不同版本做兼容处理。
