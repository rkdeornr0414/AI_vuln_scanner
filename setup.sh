#!/usr/bin/env bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "=== AI Security Tool Arsenal - Setup ==="
echo

# ── Go Installation ──
if command -v go &>/dev/null; then
    echo "[*] Go already installed: $(go version)"
else
    echo "[*] Installing Go..."
    GO_VERSION="1.23.6"
    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64)  GO_ARCH="amd64" ;;
        aarch64) GO_ARCH="arm64" ;;
        armv*)   GO_ARCH="armv6l" ;;
        *)       GO_ARCH="amd64" ;;
    esac
    OS=$(uname -s | tr '[:upper:]' '[:lower:]')
    GO_TAR="go${GO_VERSION}.${OS}-${GO_ARCH}.tar.gz"
    GO_URL="https://go.dev/dl/${GO_TAR}"

    echo "   Downloading ${GO_TAR}..."
    curl -fsSL "$GO_URL" -o "/tmp/${GO_TAR}"
    sudo rm -rf /usr/local/go
    sudo tar -C /usr/local -xzf "/tmp/${GO_TAR}"
    rm -f "/tmp/${GO_TAR}"

    # Add to PATH for this session
    export PATH="/usr/local/go/bin:$HOME/go/bin:$PATH"

    # Persist in shell profile
    PROFILE="$HOME/.bashrc"
    if ! grep -q '/usr/local/go/bin' "$PROFILE" 2>/dev/null; then
        echo 'export PATH="/usr/local/go/bin:$HOME/go/bin:$PATH"' >> "$PROFILE"
        echo "   Added Go to PATH in $PROFILE"
    fi

    echo "[OK] Go installed: $(go version)"
fi
echo

# ── Python venv ──
if [ ! -d ".venv" ]; then
    echo "[*] Creating Python virtual environment..."
    python3 -m venv .venv
else
    echo "[*] Virtual environment already exists."
fi

echo "[*] Installing Python dependencies..."
source .venv/bin/activate
pip install --upgrade pip -q
pip install -r requirements.txt -q

echo
echo "=== Setup complete! ==="
echo
echo "Next steps:"
echo "  1. Activate the venv:  source .venv/bin/activate"
echo "  2. List tools:         python tool_manager.py list"
echo "  3. Install all tools:  python tool_manager.py install-all"
echo "  4. (Optional) Set ANTHROPIC_API_KEY for AI features"
echo
