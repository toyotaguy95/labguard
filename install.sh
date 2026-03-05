#!/usr/bin/env bash
# LabGuard Installer
# One-command setup for new installations.
# Usage: git clone https://github.com/toyotaguy95/labguard.git && cd labguard && ./install.sh

set -e  # Exit on any error

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color
BOLD='\033[1m'

info()  { echo -e "${GREEN}[+]${NC} $1"; }
warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
error() { echo -e "${RED}[x]${NC} $1"; }

echo ""
echo -e "${BOLD}    LabGuard Installer${NC}"
echo -e "    AI Security Agent for Homelabs"
echo ""

# ── Check prerequisites ──
info "Checking prerequisites..."

if ! command -v python3 &>/dev/null; then
    error "Python 3 is required. Install it with: sudo apt install python3"
    exit 1
fi

PYTHON_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
PYTHON_MAJOR=$(echo "$PYTHON_VERSION" | cut -d. -f1)
PYTHON_MINOR=$(echo "$PYTHON_VERSION" | cut -d. -f2)

if [ "$PYTHON_MAJOR" -lt 3 ] || ([ "$PYTHON_MAJOR" -eq 3 ] && [ "$PYTHON_MINOR" -lt 10 ]); then
    error "Python 3.10+ required (found $PYTHON_VERSION)"
    exit 1
fi

info "Python $PYTHON_VERSION found"

# ── Install system dependencies ──
info "Installing system dependencies..."
sudo apt update -qq
sudo apt install -y -qq python3-venv rsyslog > /dev/null 2>&1
info "System dependencies installed"

# ── Create virtual environment ──
if [ ! -d "venv" ]; then
    info "Creating virtual environment..."
    python3 -m venv venv
else
    info "Virtual environment already exists"
fi

source venv/bin/activate

# ── Install Python dependencies ──
info "Installing Python dependencies..."
pip install -q pyyaml
info "Python dependencies installed"

# ── Create config file ──
if [ ! -f "config.yaml" ]; then
    cp config.example.yaml config.yaml
    warn "Created config.yaml from template"
    warn "Edit it with your settings: nano config.yaml"
    echo ""
    echo -e "  ${BOLD}Required:${NC}"
    echo "    - LLM provider (Ollama is default, free, and local)"
    echo "    - Sanitizer hostnames and domains (for privacy)"
    echo ""
    echo -e "  ${BOLD}Optional:${NC}"
    echo "    - Telegram or Discord webhook for alerts"
    echo ""
else
    info "config.yaml already exists, keeping it"
fi

# ── Set up rsyslog receiver ──
if [ ! -f "/etc/rsyslog.d/10-labguard-receiver.conf" ]; then
    info "Setting up rsyslog receiver on TCP 514..."
    sudo mkdir -p /var/log/labguard
    sudo chown root:adm /var/log/labguard
    sudo chmod 750 /var/log/labguard

    sudo tee /etc/rsyslog.d/10-labguard-receiver.conf > /dev/null <<'RSYSLOG'
# LabGuard: Receive logs from remote systems via TCP syslog
module(load="imtcp")
input(type="imtcp" port="514" ruleset="remote")

template(name="RemoteByProgram" type="string"
  string="/var/log/labguard/%programname%.log")

ruleset(name="remote") {
  $FileOwner root
  $FileGroup adm
  $FileCreateMode 0640
  action(type="omfile" dynaFile="RemoteByProgram")
  stop
}
RSYSLOG

    sudo systemctl restart rsyslog
    info "rsyslog receiver configured"
else
    info "rsyslog receiver already configured"
fi

# ── Add current user to adm group (to read logs) ──
if ! groups | grep -q adm; then
    sudo usermod -aG adm "$USER"
    warn "Added $USER to adm group (log out and back in for this to take effect)"
else
    info "User already in adm group"
fi

# ── Install systemd service ──
info "Installing systemd service..."
INSTALL_DIR=$(pwd)
VENV_PYTHON="$INSTALL_DIR/venv/bin/python3"

# Generate service file with correct paths
sudo tee /etc/systemd/system/labguard.service > /dev/null <<EOF
[Unit]
Description=LabGuard AI Security Agent
After=network-online.target rsyslog.service
Wants=network-online.target

[Service]
Type=simple
User=$USER
Group=$USER
WorkingDirectory=$INSTALL_DIR
Environment=PYTHONUNBUFFERED=1
ExecStart=$VENV_PYTHON -m labguard
Restart=on-failure
RestartSec=30

NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=$INSTALL_DIR/labguard_findings.log $INSTALL_DIR/labguard.db $INSTALL_DIR/labguard.db-journal
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable labguard
info "systemd service installed and enabled"

# ── Done ──
echo ""
echo -e "${GREEN}${BOLD}    LabGuard installed successfully!${NC}"
echo ""
echo "  Next steps:"
echo "    1. Edit your config:     nano config.yaml"
echo "    2. Test one cycle:       source venv/bin/activate && python3 -m labguard --once"
echo "    3. Test alerts:          python3 -m labguard --test-alerts"
echo "    4. Start the service:    sudo systemctl start labguard"
echo "    5. Check status:         sudo systemctl status labguard"
echo "    6. View live logs:       sudo journalctl -u labguard -f"
echo ""
echo "  Configure your router/firewall to forward syslog to this machine on TCP 514."
echo "  See docs/setup.md for detailed instructions."
echo ""
