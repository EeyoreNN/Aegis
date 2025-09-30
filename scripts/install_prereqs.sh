#!/usr/bin/env bash

set -euo pipefail

if command -v rustup >/dev/null 2>&1; then
  echo "Rustup already installed (version $(rustup --version))."
else
  echo "Installing Rust toolchain via rustup…"
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
  export PATH="$HOME/.cargo/bin:$PATH"
fi

echo "Ensuring stable toolchain is installed and up to date…"
rustup toolchain install stable >/dev/null 2>&1 || true
rustup default stable >/dev/null 2>&1 || true
rustup update stable

echo "Rust and Cargo are ready. Build the project with:"
echo "  cargo build"
