# SFT Windows Installer - Complete Build Guide

## Overview

This document describes the complete process for building a standalone Windows installer for the SFT (Secure File Transfer) Rust implementation. The installer packages Python runtime, Rust crypto module, and all dependencies into a single `.exe` file.

## Installer Architecture

### Technology Stack

- **Packaging**: Inno Setup 6.x (mature, open-source Windows installer creator)
- **Python Runtime**: Embedded Python 3.11.9 (standalone, ~30MB)
- **Crypto Module**: Rust `crypto_accelerator` compiled to `.pyd` (MSVC ABI)
- **Dependencies**: Pre-installed Python packages (cryptography, PyNaCl, etc.)
- **Target Platforms**: Windows 8, 8.1, 10, 11 (x86_64 only)

### Installer Components

```
SFT-Setup-1.8.0-win64.exe
│
├── Python 3.11.9 Embedded Runtime (~30 MB)
│   ├── python311.dll
│   ├── python.exe
│   └── Standard library
│
├── Rust Crypto Module
│   └── crypto_accelerator.cp311-win_amd64.pyd
│
├── SFT Application Files
│   ├── sft.py (main transfer protocol)
│   ├── python_wrapper.py (crypto wrapper)
│   └── Documentation
│
├── Pre-installed Dependencies
│   ├── cryptography
│   ├── PyNaCl
│   └── Other requirements.txt packages
│
└── Launcher Scripts
    ├── sft.bat (general launcher)
    ├── sft-server.bat (server mode)
    └── sft-client.bat (client mode)
```

### Installation Directory Structure

```
C:\Program Files\SFT\
├── python\                     # Embedded Python runtime
│   ├── python.exe
│   ├── python311.dll
│   ├── python311._pth          # Path configuration
│   └── Lib\
│       └── site-packages\      # Pre-installed dependencies
│           ├── cryptography\
│           ├── nacl\
│           └── crypto_accelerator.cp311-win_amd64.pyd
│
├── sft.py                      # Main application
├── python_wrapper.py           # Crypto wrapper
├── sft.bat                     # CLI launcher
├── sft-server.bat              # Server launcher
├── sft-client.bat              # Client launcher
├── README.md                   # Documentation
└── sft.ico                     # Application icon
```

## Build Requirements

### Windows Native Build

**Required Software:**
- Windows 8 or later (Windows 10/11 recommended)
- [Rust toolchain](https://rustup.rs/) (latest stable)
  - Target: `x86_64-pc-windows-msvc`
  - MSVC build tools (installed via rustup)
- [Python 3.11+](https://www.python.org/downloads/)
- [Inno Setup 6.x](https://jrsoftware.org/isdl.php)
- Internet connection (for downloading Python embedded package)

**Optional:**
- Code signing certificate (for digital signatures)

### Linux Cross-Compilation Build

**Required Software:**
- Linux (Ubuntu 20.04+ recommended)
- [Rust toolchain](https://rustup.rs/) with Windows target
  ```bash
  rustup target add x86_64-pc-windows-msvc
  ```
- Python 3.11+
- [cargo-xwin](https://github.com/rust-cross/cargo-xwin) (preferred)
  ```bash
  cargo install cargo-xwin
  ```
  OR [cargo-zigbuild](https://github.com/rust-cross/cargo-zigbuild) (alternative)
  ```bash
  cargo install cargo-zigbuild
  ```
- Wine (optional, for running Inno Setup on Linux)
  ```bash
  sudo apt install wine wine64
  ```

## Build Instructions

### Method 1: Native Windows Build (Recommended)

1. **Install Prerequisites**

   ```powershell
   # Install Rust (if not already installed)
   # Download from https://rustup.rs/ and run installer

   # Verify Rust installation
   rustc --version
   rustup target list --installed  # Should show x86_64-pc-windows-msvc

   # Install Python 3.11+
   # Download from https://www.python.org/downloads/

   # Install maturin
   pip install maturin

   # Install Inno Setup 6.x
   # Download from https://jrsoftware.org/isdl.php
   ```

2. **Clone Repository and Navigate to Rust Implementation**

   ```powershell
   git clone https://github.com/yourusername/SFT.git
   cd "SFT\Linux_and _other_distribution_(RUST)"
   git checkout feature-windows-installer
   ```

3. **Run Build Script**

   ```powershell
   # Full automated build
   .\installer\build-installer.ps1

   # Or with options:
   .\installer\build-installer.ps1 -Verbose

   # Skip steps if already done:
   .\installer\build-installer.ps1 -SkipRustBuild -SkipPythonDownload
   ```

4. **Build Output**

   The installer will be created at:
   ```
   installer\output\SFT-Setup-1.8.0-win64.exe
   ```

   Expected size: ~50-70 MB (compressed)

### Method 2: Linux Cross-Compilation

1. **Install Prerequisites**

   ```bash
   # Install Rust with Windows target
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   rustup target add x86_64-pc-windows-msvc

   # Install cargo-xwin (preferred for MSVC targets)
   cargo install cargo-xwin

   # Install Python and pip
   sudo apt update
   sudo apt install python3 python3-pip unzip wget

   # Install maturin
   pip3 install --user maturin

   # Optional: Install Wine for Inno Setup
   sudo dpkg --add-architecture i386
   sudo apt update
   sudo apt install wine wine32 wine64
   ```

2. **Clone Repository**

   ```bash
   git clone https://github.com/yourusername/SFT.git
   cd "SFT/Linux_and _other_distribution_(RUST)"
   git checkout feature-windows-installer
   ```

3. **Run Cross-Compilation Build Script**

   ```bash
   # Make script executable
   chmod +x installer/build-installer-linux.sh

   # Run build
   ./installer/build-installer-linux.sh
   ```

4. **Finalize on Windows (if Wine not available)**

   If Inno Setup compilation via Wine fails, transfer the `installer/` directory to a Windows machine and run:

   ```powershell
   # Install Inno Setup on Windows
   # Then compile:
   & "C:\Program Files (x86)\Inno Setup 6\ISCC.exe" installer\sft-setup.iss
   ```

## Build Process Details

### Step-by-Step Breakdown

The build process consists of 9 automated steps:

1. **Prerequisites Check**
   - Verifies Rust, Python, maturin, Inno Setup
   - Ensures Windows MSVC target is installed

2. **Rust Module Compilation**
   - Compiles `crypto_accelerator` Rust library to `.pyd`
   - Uses `maturin build --release --target x86_64-pc-windows-msvc`
   - Output: `target/wheels/crypto_accelerator-*.whl`

3. **Python Embedded Download**
   - Downloads `python-3.11.9-embed-amd64.zip` from python.org
   - Extracts to `installer/python-embedded/`

4. **Python Dependencies Installation**
   - Installs all `requirements.txt` packages to `installer/site-packages/`
   - Uses `pip install --target` for isolated installation
   - Cleans `__pycache__`, `.pyc`, `.dist-info` to reduce size

5. **Wheel Module Extraction**
   - Extracts `.pyd` file from compiled wheel
   - Places in `target/wheels/` for Inno Setup to bundle

6. **Launcher Script Creation**
   - Generates `sft.bat`, `sft-server.bat`, `sft-client.bat`
   - Configures `PYTHONPATH` and `PYTHON_HOME` environment variables

7. **Assets Preparation**
   - Verifies `sft.ico` icon file exists
   - Creates placeholder if missing (user should replace)

8. **VC++ Redistributable Download**
   - Downloads `vc_redist.x64.exe` (required by Rust module)
   - Installer will check and install if missing on target system

9. **Inno Setup Compilation**
   - Compiles `installer/sft-setup.iss` script
   - Creates final `SFT-Setup-1.8.0-win64.exe` in `installer/output/`

### Customization Points

**Icon File:**
Replace `installer/assets/sft.ico` with your custom icon (256x256 recommended).

**Version Bump:**
Edit `installer/sft-setup.iss`:
```pascal
#define MyAppVersion "1.8.0"  // Change version here
```

**Application Metadata:**
Edit `installer/sft-setup.iss`:
```pascal
#define MyAppPublisher "Your Name"
#define MyAppURL "https://yourwebsite.com"
```

**Digital Signature (Optional):**
Uncomment in `installer/sft-setup.iss`:
```pascal
SignTool=signtool
SignedUninstaller=yes
```
Requires code signing certificate configured in Windows.

## Troubleshooting

### Common Build Issues

**1. Rust Build Fails: "linker `link.exe` not found"**

*Cause:* MSVC build tools not installed.

*Solution:*
```bash
# Install MSVC via rustup
rustup toolchain install stable-msvc
rustup default stable-msvc
```

Or install Visual Studio Build Tools from Microsoft.

**2. maturin: "error: no Python interpreter found"**

*Cause:* Python not in PATH or wrong version.

*Solution:*
```bash
# Windows: Add Python to PATH via installer or manually
# Verify:
python --version  # Should be 3.11+
```

**3. Cross-compilation: "error: linking with `rust-lld` failed"**

*Cause:* cargo-xwin not properly configured.

*Solution:*
```bash
# Reinstall cargo-xwin
cargo install --force cargo-xwin

# Or use cargo-zigbuild instead
cargo install cargo-zigbuild
```

**4. Inno Setup: "File not found: python-embedded\python.exe"**

*Cause:* Python embedded download failed or incomplete.

*Solution:*
```bash
# Re-run build without skip flag
.\installer\build-installer.ps1  # Windows

# Or manually download and extract:
# https://www.python.org/ftp/python/3.11.9/python-3.11.9-embed-amd64.zip
# Extract to: installer/python-embedded/
```

**5. Runtime Error: "DLL load failed: The specified module could not be found"**

*Cause:* Visual C++ Redistributable missing on target system.

*Solution:* The installer automatically detects and installs VC++ Redistributable. Ensure it's not blocked by antivirus or permissions.

### Build Script Options

**PowerShell Script (`build-installer.ps1`):**

```powershell
# Skip Rust compilation (use existing .pyd)
.\installer\build-installer.ps1 -SkipRustBuild

# Skip dependency installation (use existing site-packages)
.\installer\build-installer.ps1 -SkipDependencies

# Skip Python embedded download (use existing)
.\installer\build-installer.ps1 -SkipPythonDownload

# Verbose output
.\installer\build-installer.ps1 -Verbose
```

**Bash Script (`build-installer-linux.sh`):**

No CLI flags currently; modify script directly for customization.

## Testing the Installer

### Pre-Release Testing Checklist

1. **Build Verification**
   - [ ] Installer .exe created successfully
   - [ ] File size reasonable (~50-70 MB)
   - [ ] No build errors or warnings

2. **Installation Testing**
   - [ ] Install on clean Windows 8.1 VM
   - [ ] Install on Windows 10 (21H2 or later)
   - [ ] Install on Windows 11
   - [ ] Test with non-admin account (should prompt for elevation)
   - [ ] Test custom installation directory

3. **Functional Testing**
   - [ ] Launch `sft-server.bat` - should start without errors
   - [ ] Launch `sft-client.bat --help` - should show usage
   - [ ] Check logs for "Rust acceleration module loaded successfully"
   - [ ] Perform actual file transfer between two systems
   - [ ] Verify encryption/decryption works correctly

4. **Uninstallation Testing**
   - [ ] Uninstall via Control Panel
   - [ ] Verify all files removed from installation directory
   - [ ] Check Start Menu shortcuts removed
   - [ ] Verify no leftover registry entries (optional deep check)

5. **Edge Cases**
   - [ ] Install over previous version (upgrade)
   - [ ] Install with Windows Defender enabled
   - [ ] Install with third-party antivirus
   - [ ] Install on system with Python already installed (should not conflict)

### Test Environments

**Recommended VMs:**
- Windows 8.1 x64 (minimum supported)
- Windows 10 22H2 x64
- Windows 11 23H2 x64

**Tools:**
- [VirtualBox](https://www.virtualbox.org/)
- [Windows Evaluation VMs](https://developer.microsoft.com/en-us/windows/downloads/virtual-machines/)

## Distribution

### Recommended Distribution Channels

1. **GitHub Releases**
   ```bash
   # Tag release
   git tag -a v1.8.0 -m "Windows installer release"
   git push origin v1.8.0

   # Upload installer .exe to GitHub release
   ```

2. **Checksums**
   ```powershell
   # Windows (PowerShell)
   Get-FileHash .\SFT-Setup-1.8.0-win64.exe -Algorithm SHA256

   # Linux
   sha256sum SFT-Setup-1.8.0-win64.exe
   ```

   Publish checksum alongside installer for user verification.

3. **Digital Signature (Recommended for Production)**
   - Obtain code signing certificate (EV or standard)
   - Configure in Inno Setup or use `signtool.exe` post-build
   - Reduces "Unknown Publisher" warnings on Windows

### User Installation Instructions

Provide users with:

1. **Download Link**
   - Direct link to `.exe` installer
   - SHA256 checksum for verification

2. **Installation Steps**
   ```
   1. Download SFT-Setup-1.8.0-win64.exe
   2. Right-click > Properties > Unblock (if from internet)
   3. Double-click to run installer
   4. Follow installation wizard
   5. Launch from Start Menu: "SFT Server" or "SFT Client"
   ```

3. **System Requirements**
   - Windows 8 or later (x64)
   - 100 MB disk space
   - Administrator rights for installation

## Security Considerations

### Build Security

1. **Supply Chain**
   - All dependencies downloaded over HTTPS
   - Verify Python embedded package checksum (future enhancement)
   - Pin dependency versions in `requirements.txt`

2. **Code Signing**
   - Highly recommended for production releases
   - Prevents "Unknown Publisher" warnings
   - Builds trust with users

3. **Antivirus False Positives**
   - Rust-compiled `.pyd` may trigger heuristic detection
   - Submit to antivirus vendors for whitelisting if needed
   - Consider signing with EV certificate to reduce flags

### Runtime Security

1. **Embedded Python Isolation**
   - Does not interfere with system Python
   - Uses dedicated `python311._pth` for path configuration
   - No PATH pollution

2. **Dependency Integrity**
   - All dependencies pre-installed and bundled
   - No external network calls during operation (except transfers)

3. **Uninstallation Cleanup**
   - Removes all installed files
   - Cleans up registry entries
   - Logs deleted on uninstall

## Maintenance and Updates

### Version Updates

1. Update version in `Cargo.toml`:
   ```toml
   [package]
   version = "1.9.0"
   ```

2. Update version in `installer/sft-setup.iss`:
   ```pascal
   #define MyAppVersion "1.9.0"
   ```

3. Rebuild installer with new version

### Dependency Updates

1. Update `requirements.txt` with new versions
2. Test locally
3. Rebuild installer to bundle new dependencies

### Python Version Upgrade

To upgrade embedded Python (e.g., 3.11.9 → 3.12.0):

1. Update `PYTHON_VERSION` in build scripts:
   - `installer/build-installer.ps1`: Line 12
   - `installer/build-installer-linux.sh`: Line 13

2. Update Inno Setup script:
   - `installer/sft-setup.iss`: `#define PythonVersion`

3. Rebuild Rust module for new Python version:
   ```bash
   maturin build --release --target x86_64-pc-windows-msvc
   ```

4. Ensure ABI compatibility (`.pyd` filename must match Python version)

## Advanced Topics

### Custom Python Patches

If you need to modify embedded Python:

1. Download source Python 3.11.9
2. Apply patches
3. Compile embedded distribution
4. Replace `installer/python-embedded/` with custom build

### Multi-Architecture Support

Currently supports x64 only. For x86 (32-bit) support:

1. Add Rust target: `i686-pc-windows-msvc`
2. Build separate `.pyd` for x86
3. Create separate Inno Setup script for x86
4. Download Python embedded x86 version

### Automated CI/CD

Example GitHub Actions workflow (future enhancement):

```yaml
name: Build Windows Installer

on:
  push:
    tags:
      - 'v*'

jobs:
  build-installer:
    runs-on: windows-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions-rs/toolchain@v1
        with:
          toolchain: stable
          target: x86_64-pc-windows-msvc
      - name: Build Installer
        run: .\installer\build-installer.ps1
      - name: Upload Artifact
        uses: actions/upload-artifact@v3
        with:
          name: SFT-Installer
          path: installer/output/*.exe
```

## Support and Contribution

### Reporting Issues

For installer-specific issues, include:
- Windows version (8/8.1/10/11)
- Build script output (full log)
- Installer log (if installation fails): `%TEMP%\Setup Log *.txt`

### Contributing

Improvements to the installer build process are welcome:
- Enhanced error handling
- Checksums verification
- Automated testing
- Additional platform support

Submit PRs to the `feature-windows-installer` branch.

## License

The installer scripts are part of the SFT project and follow the same license as the main project.

## Changelog

### v1.8.0 (Initial Release)
- Complete Windows installer implementation
- Inno Setup 6.x based
- Python 3.11.9 embedded runtime
- Rust crypto_accelerator integration
- Automated build scripts (PowerShell + Bash)
- Cross-compilation support (Linux → Windows)
- Windows 8-11 compatibility

---

**Author:** SFT Contributors
**Last Updated:** 2025-12-07
**Maintainer:** Sentinel (Security Lead)
