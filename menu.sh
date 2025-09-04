#!/bin/bash
# Infinity Manager - Main Menu (run as root)

USER_LIST_FILE="/etc/mk-script/users.txt"
[[ -f "$USER_LIST_FILE" ]] || { echo "User list missing at $USER_LIST_FILE"; exit 1; }

bold() { echo -e "\e[1m$1\e[0m"; }

is_any_user_online() {
  any=0
  while IFS=: read -r username limit; do
    pgrep -u "$username" sshd >/dev/null 2>&1 && { any=1; break; }
  done < "$USER_LIST_FILE"
  echo "$any"
}

show_system_dashboard() {
  echo ">> System Info Dashboard <<"
  echo "Hostname: $(hostname 2>/dev/null || echo 'Unknown')"
  echo "OS: $(lsb_release -d 2>/dev/null | cut -f2 || cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d'"' -f2 || echo 'Unknown')"
  echo "Kernel: $(uname -r 2>/dev/null || echo 'Unknown')"
  echo "Uptime: $(uptime -p 2>/dev/null | sed 's/up //' || echo 'Unknown')"
  echo "Load: $(uptime 2>/dev/null | awk -F'load average:' '{print $2}' | sed 's/,//g' || echo 'Unknown')"
  echo "CPU: $(nproc 2>/dev/null || echo 'Unknown') cores"
  echo "Memory: $(free -h 2>/dev/null | awk '/^Mem:/ {print $3 "/" $2}' || echo 'Unknown')"
  echo "Disk: $(df -h / 2>/dev/null | awk 'NR==2 {print $3 "/" $2 " (" $5 " used)"}' || echo 'Unknown')"
  echo "Network: $(ip route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev") {print $(i+1); exit}}' || echo "Unknown")"
  echo "SSH: $(systemctl is-active ssh 2>/dev/null || systemctl is-active sshd 2>/dev/null || echo "Inactive")"
  echo "SSL Tunnel: $(systemctl is-active stunnel4 2>/dev/null || echo "Inactive")"
  echo "BadVPN: $(systemctl is-active badvpn 2>/dev/null || echo "Inactive")"
  echo "Fail2Ban: $(systemctl is-active fail2ban 2>/dev/null || echo "Inactive")"
  echo "WebSocket SSH: $(systemctl is-active ssh-websocket 2>/dev/null || echo "Inactive")"
}

print_menu() {
  clear
  show_system_dashboard
  echo
  echo "========================================"
  echo "      Infinity Manager - Main Menu"
  echo "========================================"
  echo "1) Create User"
  echo "2) Delete User"
  echo "3) Limit User"
  echo "4) Connection Mode"
  ONLINE_DOT="•"; [[ "$(is_any_user_online)" -eq 1 ]] && ONLINE_DOT=$(bold "•")
  echo "5) Online Users  [$ONLINE_DOT]"
  echo "6) Kill Active Sessions"
  echo "7) Optimization"
  echo "8) Change Password"
  echo "9) Traffic"
  echo "10) Fail2Ban Integration"
  echo "11) SSH WebSocket"
  echo "12) Uninstall"
  echo "========================================"
  echo -n "Select an option [1-12]: "
}

generate_password(){ < /dev/urandom tr -dc 'A-Za-z0-9' | head -c8; }
list_users(){ nl -w2 -s ') ' "$USER_LIST_FILE"; }

create_user() {
  echo ">> Create New User <<"
  read -p "Enter new username: " username
  [[ -z "$username" ]] && { echo "Username cannot be empty."; return; }
  if id "$username" &>/dev/null; then echo "User exists. Choose another."; return; fi
  read -s -p "Enter password (blank = auto): " password; echo
  [[ -z "$password" ]] && { password=$(generate_password); echo "Generated password: $password"; }
  useradd -m -s /usr/sbin/nologin "$username" || { echo "Failed to create user."; return; }
  echo "${username}:${password}" | chpasswd
  echo "${username}:0" >> "$USER_LIST_FILE"
  if systemctl is-active --quiet stunnel4; then
    PORT=$(grep -m1 "^accept = " /etc/stunnel/stunnel.conf | awk '{print $3}')
    [[ -z "$PORT" ]] && PORT="443"
    echo "[+] '$username' created. Connection: SSH over SSL (stunnel) port $PORT."
  else
    echo "[+] '$username' created. Connection: Standard SSH port 22."
  fi
}

delete_user() {
  echo ">> Delete User <<"
  [[ -s "$USER_LIST_FILE" ]] || { echo "No users to delete."; return; }
  list_users
  read -p "Enter the number to delete: " num
  [[ "$num" =~ ^[0-9]+$ ]] || { echo "Invalid."; return; }
  username=$(sed -n "${num}p" "$USER_LIST_FILE" | cut -d: -f1)
  [[ -n "$username" ]] || { echo "Selection not found."; return; }
  userdel -r "$username" 2>/dev/null
  sed -i "${num}d" "$USER_LIST_FILE"
  LIMIT_FILE="/etc/security/limits.d/mk-script-limits.conf"
  [[ -f "$LIMIT_FILE" ]] && sed -i "/^${username}[[:space:]]\+.*maxlogins/d" "$LIMIT_FILE"
  echo "[*] Deleted '$username'."
}

limit_user() {
  echo ">> Limit User Connections <<"
  [[ -s "$USER_LIST_FILE" ]] || { echo "No users to limit."; return; }
  list_users
  read -p "Enter the number to set limit for: " num
  [[ "$num" =~ ^[0-9]+$ ]] || { echo "Invalid."; return; }
  username=$(sed -n "${num}p" "$USER_LIST_FILE" | cut -d: -f1)
  [[ -n "$username" ]] || { echo "Selection not found."; return; }
  read -p "Max simultaneous logins for '$username' (0 = unlimited): " limit
  [[ -z "$limit" || "$limit" -lt 0 ]] && limit=0
  awk -F: -v user="$username" -v newlimit="$limit" '{if($1==user){$2=newlimit} print $1 ":" $2}' "$USER_LIST_FILE" > "${USER_LIST_FILE}.tmp" && mv "${USER_LIST_FILE}.tmp" "$USER_LIST_FILE"
  LIMIT_FILE="/etc/security/limits.d/mk-script-limits.conf"
  mkdir -p /etc/security/limits.d
  sed -i "/^${username}[[:space:]]\+.*maxlogins/d" "$LIMIT_FILE" 2>/dev/null
  [[ "$limit" -gt 0 ]] && echo "${username}    -    maxlogins    $limit" >> "$LIMIT_FILE"
  echo "[*] '$username' limit set to $limit (0 = unlimited)."
}

configure_tunnel_service() {
  read -p "Port for stunnel [default 443]: " port
  port=${port:-443}
  [[ "$port" =~ ^[0-9]+$ ]] && [[ "$port" -ge 1 && "$port" -le 65535 ]] || { echo "Invalid port."; return; }
  if ! command -v stunnel &>/dev/null; then
    apt-get update -y && apt-get install -y stunnel4 || { echo "stunnel install failed."; return; }
    sed -i 's/ENABLED=0/ENABLED=1/' /etc/default/stunnel4
  fi
  if [[ ! -f /etc/stunnel/stunnel.pem ]]; then
    echo "[*] Generating stunnel certificate..."
    openssl req -newkey rsa:4096 -x509 -sha256 -days 3650 -nodes \
      -subj "/C=US/ST=State/L=City/O=MK-Script/OU=IT/CN=$(hostname)" \
      -keyout /etc/stunnel/key.pem -out /etc/stunnel/cert.pem
    cat /etc/stunnel/key.pem /etc/stunnel/cert.pem > /etc/stunnel/stunnel.pem
    chmod 600 /etc/stunnel/stunnel.pem
  fi
  cat > /etc/stunnel/stunnel.conf <<EOC
sslVersion = TLSv1.3
ciphersuites = TLS_AES_256_GCM_SHA384
options = NO_SSLv2
options = NO_SSLv3
options = NO_TLSv1
options = NO_TLSv1.1
options = NO_TLSv1.2
options = NO_COMPRESSION
options = NO_TICKET

[ssh-tunnel]
accept = ${port}
connect = 127.0.0.1:22
cert = /etc/stunnel/stunnel.pem
EOC
  systemctl enable stunnel4
  systemctl restart stunnel4
  echo "[+] SSH-SSL tunneling enabled on port $port (persists after reboot)."
}

disable_tunnel_service() {
  systemctl stop stunnel4 2>/dev/null
  systemctl disable stunnel4 2>/dev/null
  echo "[*] SSH-SSL tunneling disabled."
}

connection_mode_menu() {
  echo ">> Connection Mode <<"
  SSL_DOT="•"; systemctl is-active --quiet stunnel4 && SSL_DOT=$(bold "•")
  BADVPN_DOT="•"; systemctl is-active --quiet badvpn && BADVPN_DOT=$(bold "•")
  FAIL2BAN_DOT="•"; systemctl is-active --quiet fail2ban && FAIL2BAN_DOT=$(bold "•")
  WEBSOCKET_DOT="•"; systemctl is-active --quiet ssh-websocket && WEBSOCKET_DOT=$(bold "•")
  echo "1) SSL Tunnel [$SSL_DOT]"
  echo "2) BadVPN UDPGW (7300) [$BADVPN_DOT]"
  echo "3) Fail2Ban Protection [$FAIL2BAN_DOT]"
  echo "4) SSH WebSocket [$WEBSOCKET_DOT]"
  echo "5) Enable/Configure SSL Tunnel"
  echo "6) Disable SSL Tunnel"
  echo "7) Enable BadVPN"
  echo "8) Disable BadVPN"
  echo "9) Enable Fail2Ban"
  echo "10) Disable Fail2Ban"
  echo "11) Enable SSH WebSocket"
  echo "12) Disable SSH WebSocket"
  echo "0) Back"
  echo -n "Select an option [0-12]: "
  read cm
  case "$cm" in
    1|5) configure_tunnel_service ;;
    2|7) enable_badvpn ;;
    3|9) enable_fail2ban ;;
    4|11) enable_ssh_websocket ;;
    6) disable_tunnel_service ;;
    8) disable_badvpn ;;
    10) disable_fail2ban ;;
    12) disable_ssh_websocket ;;
    0) ;;
    *) echo "Invalid option." ;;
  esac
}

show_online_users() {
  echo ">> Online Users <<"
  [[ -s "$USER_LIST_FILE" ]] || { echo "No users created yet."; return; }
  any=0
  while IFS=: read -r username limit; do
    sessions=$(ss -tnp 2>/dev/null | awk -v u="$username" 'BEGIN{count=0} /sshd/ && /ESTAB/ { if ($0 ~ "users:\\(\\(" u "\\)" ) count++ } END{print count}')
    if [[ "$sessions" -gt 0 ]]; then
      [[ "$any" -eq 0 ]] && { echo "Active SSH sessions:"; any=1; }
      echo " - $username: $sessions"
    fi
  done < "$USER_LIST_FILE"
  [[ "$any" -eq 0 ]] && echo "No active SSH connections for managed users."
}

optimize_system() {
  echo ">> Optimization <<"
  echo "Applying system and SSH optimizations..."
  SYSCTL_FILE="/etc/sysctl.d/99-infinity-manager.conf"
  cat > "$SYSCTL_FILE" <<EOF
# Infinity Manager optimizations
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_keepalive_time = 300
net.core.somaxconn = 1024
EOF
  sysctl --system >/dev/null 2>&1
  if [[ -f /etc/ssh/sshd_config ]]; then
    cp -n /etc/ssh/sshd_config /etc/ssh/sshd_config.bak 2>/dev/null
    sed -i 's/^#\?UseDNS.*/UseDNS no/' /etc/ssh/sshd_config
    grep -q '^UseDNS' /etc/ssh/sshd_config || echo 'UseDNS no' >> /etc/ssh/sshd_config
    sed -i 's/^#\?ClientAliveInterval.*/ClientAliveInterval 120/' /etc/ssh/sshd_config
    grep -q '^ClientAliveInterval' /etc/ssh/sshd_config || echo 'ClientAliveInterval 120' >> /etc/ssh/sshd_config
    sed -i 's/^#\?ClientAliveCountMax.*/ClientAliveCountMax 2/' /etc/ssh/sshd_config
    grep -q '^ClientAliveCountMax' /etc/ssh/sshd_config || echo 'ClientAliveCountMax 2' >> /etc/ssh/sshd_config
    systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null
  fi
  echo "[+] Optimization applied (persists after reboot)."
}

kill_active_sessions() {
  echo ">> Kill Active Sessions <<"
  [[ -s "$USER_LIST_FILE" ]] || { echo "No users to manage."; return; }
  list_users
  read -p "Enter the number to kill sessions for: " num
  [[ "$num" =~ ^[0-9]+$ ]] || { echo "Invalid."; return; }
  username=$(sed -n "${num}p" "$USER_LIST_FILE" | cut -d: -f1)
  [[ -n "$username" ]] || { echo "Selection not found."; return; }
  sessions=$(pgrep -u "$username" sshd | wc -l)
  if [[ "$sessions" -eq 0 ]]; then
    echo "No active sessions for '$username'."
    return
  fi
  echo "Found $sessions active session(s) for '$username'."
  read -p "Kill all sessions? [y/N]: " confirm
  if [[ "$confirm" =~ ^[Yy]$ ]]; then
    pkill -u "$username" sshd
    echo "[+] Killed $sessions session(s) for '$username'."
  else
    echo "Canceled."
  fi
}

enable_fail2ban() {
  echo ">> Enable Fail2Ban <<"
  if ! command -v fail2ban-client >/dev/null 2>&1; then
    echo "[*] Installing Fail2Ban..."
    apt-get update -y && apt-get install -y fail2ban || { echo "Fail2Ban install failed."; return; }
  fi
  if [[ ! -f /etc/fail2ban/jail.local ]]; then
    cat > /etc/fail2ban/jail.local <<EOF
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3
backend = auto

[sshd]
enabled = true
port = ssh
logpath = /var/log/auth.log
maxretry = 3

[sshd-ddos]
enabled = true
port = ssh
logpath = /var/log/auth.log
maxretry = 2
EOF
  fi
  systemctl enable fail2ban
  systemctl restart fail2ban
  if systemctl is-active --quiet fail2ban; then
    echo "[+] Fail2Ban enabled and active (persists after reboot)."
  else
    echo "[!] Failed to start Fail2Ban. Check: systemctl status fail2ban"
  fi
}

disable_fail2ban() {
  echo ">> Disable Fail2Ban <<"
  systemctl stop fail2ban 2>/dev/null
  systemctl disable fail2ban 2>/dev/null
  echo "[*] Fail2Ban service stopped and disabled."
}

fail2ban_menu() {
  echo ">> Fail2Ban Integration <<"
  if systemctl is-active --quiet fail2ban; then
    echo "Status: ACTIVE"
    echo "1) View Fail2Ban Status"
    echo "2) Disable Fail2Ban"
  else
    echo "Status: INACTIVE"
    echo "1) Enable Fail2Ban"
  fi
  echo "0) Back"
  echo -n "Select an option: "
  read fchoice
  case "$fchoice" in
    1) if systemctl is-active --quiet fail2ban; then fail2ban-client status; else enable_fail2ban; fi ;;
    2) disable_fail2ban ;;
    0) ;;
    *) echo "Invalid option." ;;
  esac
}

enable_ssh_websocket() {
  echo ">> Enable SSH WebSocket <<"
  if ! command -v ws-tunnel >/dev/null 2>&1; then
    echo "[*] Installing ws-tunnel..."
    if ! command -v npm >/dev/null 2>&1; then
      apt-get update -y && apt-get install -y nodejs npm || { echo "Node.js install failed."; return; }
    fi
    npm install -g ws-tunnel || { echo "ws-tunnel install failed."; return; }
  fi
  cat > /etc/systemd/system/ssh-websocket.service <<EOF
[Unit]
Description=SSH WebSocket Tunnel
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/ws-tunnel --server ws://0.0.0.0:8080 --target 127.0.0.1:22
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable ssh-websocket
  systemctl restart ssh-websocket
  if systemctl is-active --quiet ssh-websocket; then
    echo "[+] SSH WebSocket enabled on port 8080 (persists after reboot)."
  else
    echo "[!] Failed to start SSH WebSocket. Check: systemctl status ssh-websocket"
  fi
}

disable_ssh_websocket() {
  echo ">> Disable SSH WebSocket <<"
  systemctl stop ssh-websocket 2>/dev/null
  systemctl disable ssh-websocket 2>/dev/null
  echo "[*] SSH WebSocket service stopped and disabled."
}

ssh_websocket_menu() {
  echo ">> SSH WebSocket <<"
  if systemctl is-active --quiet ssh-websocket; then
    echo "Status: ACTIVE"
    echo "1) View WebSocket Status"
    echo "2) Disable WebSocket"
  else
    echo "Status: INACTIVE"
    echo "1) Enable WebSocket"
  fi
  echo "0) Back"
  echo -n "Select an option: "
  read wchoice
  case "$wchoice" in
    1) if systemctl is-active --quiet ssh-websocket; then systemctl status ssh-websocket; else enable_ssh_websocket; fi ;;
    2) disable_ssh_websocket ;;
    0) ;;
    *) echo "Invalid option." ;;
  esac
}

change_password() {
  echo ">> Change User Password <<"
  [[ -s "$USER_LIST_FILE" ]] || { echo "No users to modify."; return; }
  list_users
  read -p "Enter the number to change password for: " num
  [[ "$num" =~ ^[0-9]+$ ]] || { echo "Invalid."; return; }
  username=$(sed -n "${num}p" "$USER_LIST_FILE" | cut -d: -f1)
  [[ -n "$username" ]] || { echo "Selection not found."; return; }
  read -s -p "Enter new password: " password; echo
  [[ -z "$password" ]] && { echo "Password cannot be empty."; return; }
  echo "${username}:${password}" | chpasswd && echo "[+] Password updated for '$username'."
}

show_traffic() {
  echo ">> Traffic Usage (vnStat) <<"
  if ! command -v vnstat >/dev/null 2>&1; then
    echo "[*] Installing vnStat..."
    apt-get update -y && apt-get install -y vnstat >/dev/null 2>&1 || { echo "Failed to install vnstat."; return; }
    systemctl enable --now vnstat >/dev/null 2>&1
  fi
  IFACE=$(ip route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev") {print $(i+1); exit}}')
  [[ -z "$IFACE" ]] && IFACE=$(ip -o -4 route show to default | awk '{print $5; exit}')
  [[ -z "$IFACE" ]] && { echo "Could not detect default interface."; return; }
  vnstat -u -i "$IFACE" >/dev/null 2>&1
  systemctl start vnstat >/dev/null 2>&1
  echo "Interface: $IFACE"
  vnstat -i "$IFACE" || echo "vnStat has no data yet. Please wait a few minutes."
}

# BadVPN UDPGW management (port 7300)
ensure_badvpn_binary() {
  if [[ -x /usr/local/bin/badvpn-udpgw ]]; then return 0; fi
  echo "[*] Installing BadVPN UDPGW binary..."
  # Try apt package if available, else download static binary.
  if apt-cache show badvpn >/dev/null 2>&1; then
    apt-get update -y && apt-get install -y badvpn && command -v badvpn-udpgw >/dev/null 2>&1 && ln -sf "$(command -v badvpn-udpgw)" /usr/local/bin/badvpn-udpgw && return 0
  fi
  ARCH=$(uname -m)
  URL=""
  case "$ARCH" in
    x86_64) URL="https://github.com/yzgyyang/badvpn-udpgw-builds/releases/download/v1.0/badvpn-udpgw-x86_64" ;;
    aarch64|arm64) URL="https://github.com/yzgyyang/badvpn-udpgw-builds/releases/download/v1.0/badvpn-udpgw-arm64" ;;
    armv7l) URL="https://github.com/yzgyyang/badvpn-udpgw-builds/releases/download/v1.0/badvpn-udpgw-armv7" ;;
    *) URL="" ;;
  esac
  if [[ -n "$URL" ]]; then
    wget -O /usr/local/bin/badvpn-udpgw "$URL" && chmod +x /usr/local/bin/badvpn-udpgw && return 0
  fi
  echo "[!] Could not determine a suitable BadVPN binary for architecture: $ARCH"
  return 1
}

enable_badvpn() {
  echo ">> Enable BadVPN UDPGW (7300) <<"
  ensure_badvpn_binary || { echo "Installation of BadVPN failed."; return; }
  cat > /etc/systemd/system/badvpn.service <<EOF
[Unit]
Description=BadVPN UDPGW Service
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/badvpn-udpgw --listen-addr 0.0.0.0:7300 --max-clients 2000 --max-connections-for-client-ip 200
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable badvpn
  systemctl restart badvpn
  if systemctl is-active --quiet badvpn; then
    echo "[+] BadVPN UDPGW enabled on port 7300."
  else
    echo "[!] Failed to start BadVPN service. Check: systemctl status badvpn"
  fi
}

disable_badvpn() {
  echo ">> Disable BadVPN UDPGW <<"
  systemctl stop badvpn 2>/dev/null
  systemctl disable badvpn 2>/dev/null
  echo "[*] BadVPN service stopped and disabled."
}

manage_badvpn_menu() { :; }

uninstall_script() {
  echo ">> Uninstall Infinity Manager <<"
  read -p "Are you sure? [y/N]: " c
  [[ "$c" =~ ^[Yy]$ ]] || { echo "Canceled."; return; }
  echo "[*] Removing stunnel..."
  systemctl stop stunnel4 2>/dev/null
  systemctl disable stunnel4 2>/dev/null
  apt-get remove -y stunnel4 >/dev/null 2>&1
  rm -f /etc/stunnel/stunnel.conf /etc/stunnel/stunnel.pem /etc/stunnel/key.pem /etc/stunnel/cert.pem
  rm -f /etc/default/stunnel4 /etc/systemd/system/stunnel4.service
  systemctl daemon-reload
  echo "[*] Removing BadVPN..."
  systemctl stop badvpn 2>/dev/null
  systemctl disable badvpn 2>/dev/null
  rm -f /etc/systemd/system/badvpn.service
  systemctl daemon-reload
  rm -f /usr/local/bin/badvpn-udpgw
  echo "[*] Removing Fail2Ban..."
  systemctl stop fail2ban 2>/dev/null
  systemctl disable fail2ban 2>/dev/null
  apt-get remove -y fail2ban >/dev/null 2>&1
  echo "[*] Removing SSH WebSocket..."
  systemctl stop ssh-websocket 2>/dev/null
  systemctl disable ssh-websocket 2>/dev/null
  rm -f /etc/systemd/system/ssh-websocket.service
  systemctl daemon-reload
  npm uninstall -g ws-tunnel >/dev/null 2>&1
  echo "[*] Removing users..."
  while IFS=: read -r username limit; do
    id "$username" &>/dev/null && userdel -r "$username"
  done < "$USER_LIST_FILE"
  echo "[*] Cleaning files..."
  rm -f /usr/local/bin/menu
  rm -rf /etc/mk-script
  rm -f /etc/security/limits.d/mk-script-limits.conf
  rm -f /etc/sysctl.d/99-infinity-manager.conf
  echo "[+] Uninstalled."
  exit 0
}

while true; do
  print_menu
  read choice
  echo
  case "$choice" in
    1) create_user ;;
    2) delete_user ;;
    3) limit_user ;;
    4) connection_mode_menu ;;
    5) show_online_users ;;
    6) kill_active_sessions ;;
    7) optimize_system ;;
    8) change_password ;;
    9) show_traffic ;;
    10) fail2ban_menu ;;
    11) ssh_websocket_menu ;;
    12) uninstall_script ;;
    *) echo "Invalid option. Enter 1-12." ;;
  esac
  [[ "$choice" != "12" ]] && read -n1 -s -r -p "Press any key to return..." && echo
done
