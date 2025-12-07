# SFT Windows Installer Build Directory

This directory contains all files necessary to build the Windows installer for SFT.

## Quick Start

### Windows (Native Build)

```powershell
# Run automated build
.\build-installer.ps1
```

The installer will be created in `output/SFT-Setup-1.8.0-win64.exe`

### Linux (Cross-Compilation)

```bash
# One-time setup
./setup-build-env.sh

# Build installer
./build-installer-linux.sh
```

## Full Documentation

See [README_WINDOWS_INSTALLER.md](../README_WINDOWS_INSTALLER.md) in the parent directory for:
- Complete build instructions
- Prerequisites
- Troubleshooting
- Customization options
- Testing procedures

## Directory Structure

```
installer/
├── sft-setup.iss              # Inno Setup script (main installer config)
├── build-installer.ps1        # Windows build automation (PowerShell)
├── build-installer-linux.sh   # Linux build automation (Bash)
├── setup-build-env.sh         # One-time environment setup (Linux)
├── docs/
│   ├── pre-install.txt        # Displayed before installation
│   └── post-install.txt       # Displayed after installation
├── launchers/                 # (Auto-generated) Batch launcher scripts
├── assets/                    # (User-provided) Icons and resources
├── python-embedded/           # (Auto-generated) Python runtime
├── site-packages/             # (Auto-generated) Python dependencies
└── output/                    # (Auto-generated) Final installer .exe
```

## Build Process Overview

1. Compile Rust `crypto_accelerator` module for Windows (MSVC target)
2. Download Python 3.11.9 embedded distribution
3. Install Python dependencies to isolated directory
4. Extract `.pyd` module from wheel
5. Generate launcher scripts
6. Prepare assets (icon, etc.)
7. Download Visual C++ Redistributable
8. Compile installer with Inno Setup

## Requirements Summary

**Windows:**
- Rust toolchain (MSVC)
- Python 3.11+
- Inno Setup 6.x

**Linux:**
- Rust toolchain + Windows target
- cargo-xwin or cargo-zigbuild
- Python 3.11+
- Wine (optional, for Inno Setup)

## Support

For issues or questions, see the main documentation or open an issue on GitHub.
