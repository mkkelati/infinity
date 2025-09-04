# Infinity Manager

Professional SSH/SSL tunnel manager with BadVPN UDPGW, Fail2Ban, SSH WebSocket, optimization tools, and live system dashboard. Supports Ubuntu 20.04–24.04.

## Features
- One-command install, fully automated
- System Info Dashboard (CPU/RAM/Disk/Uptime/Services)
- User management: Create, Delete, Limit, Change Password
- Online Users with per-user session counts
- Connection Mode submenu with status dots:
  - SSL Tunnel (stunnel, TLS 1.3) – persistent
  - BadVPN UDPGW (port 7300) – persistent
  - Fail2Ban protection – persistent
  - SSH WebSocket (port 8080) – persistent
- Kill Active Sessions for a selected user
- Optimization (BBR, fq, SSH tuning) – persistent
- Traffic usage via vnStat
- Clean uninstall

## Install
```bash
# One-line installation from GitHub
sudo apt-get update -y && sudo apt-get install -y wget && \
wget -O install.sh https://raw.githubusercontent.com/mkkelati/infinity/main/install.sh && \
sudo bash install.sh

# Or step by step:
sudo apt-get update -y && sudo apt-get install -y wget
wget -O install.sh https://raw.githubusercontent.com/mkkelati/infinity/main/install.sh
sudo bash install.sh
```

## Usage
- Launch the manager:
```bash
sudo menu
```
- Connection Mode shows status dots (bold = enabled, regular = disabled) and lets you enable/disable:
  1) SSL Tunnel
  2) BadVPN UDPGW (7300)
  3) Fail2Ban
  4) SSH WebSocket (8080)
- Online Users lists each username with the number of active SSH sessions.

### HTTP Injector
- Protocol: Stunnel
- Port: 443 (or your configured SSL tunnel port)

## Uninstall
Use the Uninstall option to remove services, managed users, and related files.

## Repository
Code and updates: [`https://github.com/mkkelati/infinity`](https://github.com/mkkelati/infinity)
