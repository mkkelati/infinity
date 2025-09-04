#!/bin/bash
# install.sh - Installation script for Infinity Manager (Ubuntu 20.04 - 24.04)

if [[ "$EUID" -ne 0 ]]; then
  echo "Please run this installer as root (using sudo)."
  exit 1
fi

echo "=== Installing Infinity Manager ==="
export DEBIAN_FRONTEND=noninteractive
apt-get update -y && apt-get install -y openssl wget curl vnstat fail2ban nodejs npm

echo "[*] Installing and configuring stunnel..."
# Remove any existing stunnel packages and configs
apt-get remove -y stunnel4 2>/dev/null || true
rm -f /etc/default/stunnel4
rm -f /etc/systemd/system/stunnel4.service
rm -rf /etc/stunnel

# Install stunnel4 fresh
apt-get install -y stunnel4

# Stop any running stunnel processes
pkill stunnel4 2>/dev/null || true
systemctl stop stunnel4 2>/dev/null || true
systemctl disable stunnel4 2>/dev/null || true

# Create proper /etc/default/stunnel4 for compatibility
cat > /etc/default/stunnel4 <<EOF
# /etc/default/stunnel4
# Change to one to enable stunnel4 startup
ENABLED=1

# Change to a user with privileges to reduce security risks
# For example, to run as nobody, use UID = 65534
FILES="/etc/stunnel/*.conf"
OPTIONS=""

# Change to /var/log/stunnel4/stunnel.log if you want logging
# and create the directory with appropriate permissions
# LOG="/var/log/stunnel4/stunnel.log"
EOF

# Create systemd service that works with the default config
cat > /etc/systemd/system/stunnel4.service <<EOF
[Unit]
Description=LSSL tunnel for network daemons
After=network.target

[Service]
Type=forking
ExecStart=/usr/bin/stunnel4 /etc/default/stunnel4
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=3
PIDFile=/var/run/stunnel4/stunnel4.pid

[Install]
WantedBy=multi-user.target
EOF

mkdir -p /etc/stunnel
STUNNEL_CERT="/etc/stunnel/stunnel.pem"
if [[ ! -f "$STUNNEL_CERT" ]]; then
  echo "[*] Generating self-signed SSL certificate for stunnel..."
  openssl req -newkey rsa:4096 -x509 -sha256 -days 3650 -nodes \
    -subj "/C=US/ST=State/L=City/O=Infinity-Manager/OU=IT/CN=$(hostname)" \
    -keyout /etc/stunnel/key.pem -out /etc/stunnel/cert.pem
  cat /etc/stunnel/key.pem /etc/stunnel/cert.pem > "$STUNNEL_CERT"
  chmod 600 "$STUNNEL_CERT"
fi

STUNNEL_CONF="/etc/stunnel/stunnel.conf"
if [[ ! -f "$STUNNEL_CONF" ]]; then
  echo "[*] Setting up stunnel configuration..."
  cat > "$STUNNEL_CONF" << 'EOC'
# stunnel configuration for SSH-SSL tunneling (Infinity Manager)
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
accept = 443
connect = 127.0.0.1:22
cert = /etc/stunnel/stunnel.pem
EOC
fi

echo "[*] Starting stunnel service..."
# Create PID directory
mkdir -p /var/run/stunnel4
chown stunnel4:stunnel4 /var/run/stunnel4 2>/dev/null || true

systemctl daemon-reload
systemctl enable stunnel4

# Test if stunnel config is valid before starting
if /usr/bin/stunnel4 -test /etc/stunnel/stunnel.conf 2>/dev/null; then
  systemctl start stunnel4
  sleep 2
  if systemctl is-active --quiet stunnel4; then
    echo "[+] stunnel4 service started successfully"
  else
    echo "[!] stunnel4 failed to start. Trying alternative approach..."
    # Try starting with the default init script
    /etc/init.d/stunnel4 start 2>/dev/null || true
    sleep 2
    if systemctl is-active --quiet stunnel4 || pgrep stunnel4 >/dev/null; then
      echo "[+] stunnel4 started with alternative method"
    else
      echo "[!] stunnel4 failed to start. Check: systemctl status stunnel4"
      echo "[*] You can enable it later from the menu"
    fi
  fi
else
  echo "[!] stunnel4 configuration is invalid. Service not started."
  echo "[*] You can configure it later from the menu"
fi

echo "[*] Deploying menu script..."
INSTALL_DIR="/usr/local/bin"
# Download menu.sh from GitHub if not present locally
if [[ ! -f "menu.sh" ]]; then
  echo "[*] Downloading menu.sh from GitHub..."
  wget -q https://raw.githubusercontent.com/mkkelati/infinity/main/menu.sh
fi
cp -f menu.sh "${INSTALL_DIR}/menu"
chmod +x "${INSTALL_DIR}/menu"

mkdir -p /etc/mk-script
touch /etc/mk-script/users.txt

# Setup BadVPN systemd (disabled by default)
if [[ ! -f /etc/systemd/system/badvpn.service ]]; then
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
fi

# Setup vnStat for traffic monitoring
echo "[*] Configuring vnStat..."
systemctl enable vnstat 2>/dev/null || true
systemctl start vnstat 2>/dev/null || true

# Setup Fail2Ban (disabled by default)
echo "[*] Configuring Fail2Ban..."
if [[ ! -f /etc/fail2ban/jail.local ]]; then
  cat > /etc/fail2ban/jail.local <<EOF
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3
backend = auto

[sshd]
enabled = false
port = ssh
logpath = /var/log/auth.log
maxretry = 3

[sshd-ddos]
enabled = false
port = ssh
logpath = /var/log/auth.log
maxretry = 2
EOF
fi

# Setup SSH WebSocket service (disabled by default)
echo "[*] Configuring SSH WebSocket..."
if [[ ! -f /etc/systemd/system/ssh-websocket.service ]]; then
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
fi

# Install ws-tunnel globally
echo "[*] Installing ws-tunnel..."
npm install -g ws-tunnel 2>/dev/null || echo "[!] ws-tunnel installation failed, will install on first use"

echo "[+] Installation complete. Run 'menu' to start."
