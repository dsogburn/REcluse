#!/bin/bash
# setup.sh - Automated Environment Provisioner

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "[*] Verifying Debian/Ubuntu development dependencies..."
sudo apt update
sudo apt install -y build-essential python3-dev zlib1g-dev python3-venv docker.io p7zip-full file

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
./venv/bin/pip install litellm pyminizip pyzipper docker "mcp[cli]" fastapi uvicorn python-multipart

if [ ! -f config.json ]; then
    echo "[*] Initializing empty config.json from template..."
    cp config.json.template config.json
fi

echo "[+] Dependency installation complete."
if ! id -nG "$USER" | tr ' ' '\n' | grep -qx docker; then
    echo "[!] Your login session has not picked up Docker group membership yet."
    echo "    Log out and back in (or reboot) before running REcluse."
fi
echo "[+] Verify non-root access with: docker run --rm hello-world"
echo "[+] You can now run analyses using: ./recluse <your_sample.zip>"
