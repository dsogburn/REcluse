#!/bin/bash
# setup.sh - Automated Environment Provisioner

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "[*] Verifying Debian/Ubuntu development dependencies..."
sudo apt update
sudo apt install -y build-essential python3-dev zlib1g-dev python3-venv p7zip-full file nodejs npm

if command -v docker >/dev/null 2>&1; then
    echo "[*] Existing Docker CLI detected; preserving the installed Docker package source."
else
    echo "[*] Installing Debian Docker engine and CLI..."
    # Buildx is not required by REcluse. Avoid recommended plugin packages so
    # Debian's docker-buildx cannot collide with Docker CE's buildx plugin on a
    # host that has used both repositories.
    DOCKER_PACKAGES=(docker.io)
    if apt-cache show docker-cli >/dev/null 2>&1; then
        DOCKER_PACKAGES+=(docker-cli)
    fi
    sudo apt install -y --no-install-recommends "${DOCKER_PACKAGES[@]}"
fi

echo "[*] Configuring non-root Docker access..."
if ! getent group docker >/dev/null; then
    sudo groupadd docker
fi
sudo usermod -aG docker "$USER"
sudo systemctl enable --now docker

echo "[*] Spinning up local Python Virtual Environment..."
if [ ! -d venv ]; then
    python3 -m venv venv
fi

echo "[*] Installing Python packages inside the venv..."
./venv/bin/pip install --upgrade pip
./venv/bin/pip install litellm pyminizip pyzipper docker requests "mcp[cli]>=1.28,<2" fastapi uvicorn python-multipart anyrun-sdk jbxapi

echo "[*] Installing the REMnux MCP Scenario 1 connector..."
npm install --omit=dev

if [ ! -f config.json ]; then
    echo "[*] Initializing empty config.json from template..."
    cp config.json.template config.json
fi

echo "[*] Installing localhost WebGUI systemd service..."
INSTALL_USER="${SUDO_USER:-$(stat -c '%U' "$SCRIPT_DIR")}"
if [ "$INSTALL_USER" = "root" ]; then
    echo "[-] Refusing to install the WebGUI service as root."
    echo "    Run setup.sh from a non-root checkout as that user (do not prefix the script with sudo)."
    exit 1
fi
escape_sed_replacement() {
    printf '%s' "$1" | sed 's/[&|\\]/\\&/g'
}
SERVICE_USER="$(escape_sed_replacement "$INSTALL_USER")"
SERVICE_DIR="$(escape_sed_replacement "$SCRIPT_DIR")"
if [[ "$SCRIPT_DIR" =~ [[:space:]] ]]; then
    echo "[-] The system service requires a checkout path without whitespace: $SCRIPT_DIR"
    exit 1
fi
SERVICE_TEMP="$(mktemp --suffix=.service)"
trap 'rm -f "$SERVICE_TEMP"' EXIT
sed \
    -e "s|@RECLUSE_USER@|$SERVICE_USER|g" \
    -e "s|@RECLUSE_DIR@|$SERVICE_DIR|g" \
    recluse-web.service.in > "$SERVICE_TEMP"
systemd-analyze verify "$SERVICE_TEMP"
sudo install -o root -g root -m 0644 "$SERVICE_TEMP" /etc/systemd/system/recluse-web.service
sudo systemctl daemon-reload
sudo systemctl enable recluse-web.service
sudo systemctl restart recluse-web.service

echo "[+] Dependency installation complete."
if ! id -nG "$USER" | tr ' ' '\n' | grep -qx docker; then
    echo "[!] Your login session has not picked up Docker group membership yet."
    echo "    Log out and back in (or reboot) before running REcluse."
fi
echo "[+] Verify non-root access with: docker run --rm hello-world"
echo "[+] You can now run analyses using: ./recluse <your_sample.zip>"
echo "[+] WebGUI enabled at: http://127.0.0.1:8743"
echo "[+] Service status: systemctl status recluse-web.service"
