#!/usr/bin/env bash
# ==============================================================================
# SFT Windows Installer - Build Environment Setup
# One-time setup script for cross-compilation environment (Linux)
# ==============================================================================

set -euo pipefail

COLOR_RESET="\033[0m"
COLOR_CYAN="\033[0;36m"
COLOR_GREEN="\033[0;32m"
COLOR_YELLOW="\033[0;33m"
COLOR_RED="\033[0;31m"

echo -e "${COLOR_CYAN}========================================"
echo -e "SFT Build Environment Setup"
echo -e "========================================${COLOR_RESET}"
echo ""

# Install Rust if not present
if ! command -v rustc &> /dev/null; then
    echo -e "${COLOR_YELLOW}Installing Rust toolchain...${COLOR_RESET}"
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source "$HOME/.cargo/env"
    echo -e "${COLOR_GREEN}✓ Rust installed${COLOR_RESET}"
else
    echo -e "${COLOR_GREEN}✓ Rust already installed: $(rustc --version)${COLOR_RESET}"
fi

# Add Windows MSVC target
echo -e "${COLOR_YELLOW}Adding Windows MSVC target...${COLOR_RESET}"
rustup target add x86_64-pc-windows-msvc
echo -e "${COLOR_GREEN}✓ Windows target added${COLOR_RESET}"

# Install cargo-xwin (preferred cross-compilation tool)
if ! command -v cargo-xwin &> /dev/null; then
    echo -e "${COLOR_YELLOW}Installing cargo-xwin...${COLOR_RESET}"
    cargo install cargo-xwin
    echo -e "${COLOR_GREEN}✓ cargo-xwin installed${COLOR_RESET}"
else
    echo -e "${COLOR_GREEN}✓ cargo-xwin already installed${COLOR_RESET}"
fi

# Install maturin
if ! command -v maturin &> /dev/null; then
    echo -e "${COLOR_YELLOW}Installing maturin...${COLOR_RESET}"
    pip3 install --user maturin
    export PATH="$HOME/.local/bin:$PATH"
    echo -e "${COLOR_GREEN}✓ maturin installed${COLOR_RESET}"
else
    echo -e "${COLOR_GREEN}✓ maturin already installed${COLOR_RESET}"
fi

# Verify Python
if ! command -v python3 &> /dev/null; then
    echo -e "${COLOR_RED}ERROR: Python 3 not found. Please install Python 3.11+${COLOR_RESET}"
    exit 1
else
    echo -e "${COLOR_GREEN}✓ Python: $(python3 --version)${COLOR_RESET}"
fi

# Check for required system tools
echo -e "${COLOR_YELLOW}Checking system tools...${COLOR_RESET}"

missing_tools=()

for tool in wget curl unzip; do
    if ! command -v "$tool" &> /dev/null; then
        missing_tools+=("$tool")
    fi
done

if [ ${#missing_tools[@]} -gt 0 ]; then
    echo -e "${COLOR_YELLOW}Missing tools: ${missing_tools[*]}${COLOR_RESET}"
    echo -e "${COLOR_YELLOW}Install with: sudo apt install ${missing_tools[*]}${COLOR_RESET}"
else
    echo -e "${COLOR_GREEN}✓ All required tools present${COLOR_RESET}"
fi

echo ""
echo -e "${COLOR_GREEN}========================================"
echo -e "Setup Complete!"
echo -e "========================================${COLOR_RESET}"
echo ""
echo -e "${COLOR_CYAN}You can now build the Windows installer with:${COLOR_RESET}"
echo -e "  ./installer/build-installer-linux.sh"
echo ""
