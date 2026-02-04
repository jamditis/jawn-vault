#!/bin/bash
# Jawn Vault setup script
# Installs Rust and builds the project

set -e

echo "=== Jawn Vault Setup ==="

# Check for curl
if ! command -v curl &> /dev/null; then
    echo "Error: curl is required but not installed"
    exit 1
fi

# Install Rust if not present
if ! command -v rustc &> /dev/null; then
    echo "Installing Rust via rustup..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source "$HOME/.cargo/env"
else
    echo "Rust already installed: $(rustc --version)"
fi

# Ensure cargo is in PATH
export PATH="$HOME/.cargo/bin:$PATH"

# Move to project directory
cd "$(dirname "$0")/.."

echo "Building jawn-vault (this may take a while on first run)..."
cargo build --release

echo ""
echo "=== Build complete ==="
echo ""
echo "Binaries:"
echo "  ./target/release/jawn-vault    # Daemon"
echo "  ./target/release/vault-cli     # CLI tool"
echo ""
echo "Next steps:"
echo "  1. Copy config: cp deploy/config.example.toml ~/.config/jawn-vault/config.toml"
echo "  2. Start daemon: ./target/release/jawn-vault --foreground"
echo "  3. Create token: ./target/release/vault-cli token create myapp --grant '**' -p admin"
echo ""
