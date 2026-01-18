#!/bin/bash
cd C/

# Install system dependencies
sudo apt install build-essential python3-dev libssl-dev python3-pip

# Setup virtual environment
python3 -m venv venv
source venv/bin/activate

# Install Python dependencies and compile C module
pip install -r requirements.txt
python3 python_wrapper.py --compile

# Start server
python3 sft.py --mode server --port 5555

# Transfer file (from another terminal)
python3 sft.py --mode client --connect localhost:5555 --file document.pdf
# Verify installation
python3 python_wrapper.py --test
echo "Installation complete. You can now use the Secure File Transfer application."
# Note: Ensure you have gcc installed for compiling the C module.