#!/bin/bash

sudo apt update
sudo apt install -y build-essential python3-dev python3-pip git python3-venv git

# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
sleep 5

# Check versions
python3 --version          # Should be >= 3.9
rustc --version           # Should be >= 1.70
cargo --version           # Should be >= 1.70
pip3 --version              # Should be >= 20.0
git --version            # Should be >= 2.25

# 1. Clone the repository
git clone https://github.com/Yul-1/Secure-File-Transfer
cd SFT/RUST

# 2. Create virtual environment (recommended)
python3 -m venv venv
sleep 2
source venv/bin/activate  # Linux/macOS

# 3. Install Python dependencies
pip install -r requirements.txt

# 4. Compile Rust module (optional but recommended for performance)
python3 python_wrapper.py --compile

# 5. Verify installation
python3 python_wrapper.py --test
echo "Installation complete. You can now use the Secure File Transfer application."
