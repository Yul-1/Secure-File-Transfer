# Quick Build Test Guide

## Pre-Build Verification

Before running the full build, verify the project structure:

```bash
# From Linux_and _other_distribution_(RUST)/ directory

# Check installer structure
ls -R installer/

# Expected structure:
# installer/
# ├── sft-setup.iss
# ├── build-installer.ps1
# ├── build-installer-linux.sh
# ├── setup-build-env.sh
# ├── README.md
# ├── TEST_BUILD.md
# ├── assets/
# │   ├── .gitkeep
# │   └── README.txt
# ├── docs/
# │   ├── pre-install.txt
# │   └── post-install.txt
# ├── launchers/
# │   └── .gitkeep
# └── output/
#     └── .gitkeep

# Verify main files exist
ls sft.py python_wrapper.py requirements.txt Cargo.toml src/lib.rs
```

## Test Cross-Compilation (Linux)

Test Rust module compilation for Windows without running full installer build:

```bash
# Setup environment (one-time)
./installer/setup-build-env.sh

# Test cross-compile Rust module only
cd ..  # Back to project root
maturin build --release --target x86_64-pc-windows-msvc

# Check output
ls -lh target/wheels/
# Should see: crypto_accelerator-1.8.0-cp311-cp311-win_amd64.whl
```

## Test Native Rust Build (Any Platform)

Verify Rust module compiles for current platform:

```bash
# From Linux_and _other_distribution_(RUST)/
maturin develop --release

# Test import in Python
python3 -c "import crypto_accelerator; print('Rust module loaded successfully')"
```

## Dry Run Checks

Verify all prerequisites without actually building:

### Linux

```bash
./installer/build-installer-linux.sh 2>&1 | head -n 50
# Should pass step [1/9] Prerequisites check
# Press Ctrl+C to abort after verification
```

### Windows

```powershell
# In PowerShell
.\installer\build-installer.ps1 -WhatIf
# Note: -WhatIf not implemented, but script will fail early if prerequisites missing
```

## Minimal Build Test (Windows)

If on Windows, test individual build steps:

```powershell
# Test Rust build only
cd ..
maturin build --release --target x86_64-pc-windows-msvc
ls target\wheels\

# Test Python download
$url = "https://www.python.org/ftp/python/3.11.9/python-3.11.9-embed-amd64.zip"
Invoke-WebRequest -Uri $url -OutFile test-python.zip
# Clean up: Remove-Item test-python.zip

# Test pip install to custom directory
pip install --target test-site-packages -r requirements.txt
# Clean up: Remove-Item -Recurse test-site-packages
```

## Expected Build Times

- **Rust module compilation**: 2-5 minutes (first time), 30s-1min (incremental)
- **Python download**: 1-2 minutes (30MB download)
- **Dependency installation**: 3-5 minutes (cryptography has native extensions)
- **Inno Setup compilation**: 30 seconds - 1 minute
- **Total (first build)**: ~10-15 minutes
- **Total (incremental)**: ~5 minutes

## Common Issues During Testing

### Issue: "error: linker `rust-lld` failed"

**Cause**: Cross-compilation linker not found

**Fix**:
```bash
# Install cargo-xwin
cargo install cargo-xwin

# Or use cargo-zigbuild
cargo install cargo-zigbuild
```

### Issue: "ImportError: DLL load failed while importing crypto_accelerator"

**Cause**: Wrong Python version or ABI mismatch

**Fix**: Ensure Python 3.11.x is used (not 3.10 or 3.12)

### Issue: "ModuleNotFoundError: No module named 'maturin'"

**Fix**:
```bash
pip3 install --user maturin
export PATH="$HOME/.local/bin:$PATH"
```

### Issue: Inno Setup not found (Linux)

**Expected**: This is normal. Complete final compilation step on Windows or setup Wine:

```bash
# Install Wine
sudo apt install wine wine64

# Install Inno Setup in Wine
wget https://files.jrsoftware.org/is/6/innosetup-6.2.2.exe
wine innosetup-6.2.2.exe
# Follow GUI installer
```

## Post-Build Verification

After successful build, verify installer:

```bash
# Check output file exists
ls -lh installer/output/SFT-Setup-*.exe

# Verify file is not empty
file installer/output/SFT-Setup-*.exe
# Should show: "PE32+ executable (GUI) x86-64, for MS Windows"

# Check size (should be ~50-70 MB)
du -h installer/output/SFT-Setup-*.exe
```

## Next Steps

If tests pass:
1. Run full build with `./installer/build-installer-linux.sh` (Linux) or `.\installer\build-installer.ps1` (Windows)
2. Test installer on clean Windows VM
3. Verify all functionality (see README_WINDOWS_INSTALLER.md Testing section)

If tests fail:
1. Review error messages
2. Check prerequisites are installed correctly
3. Consult README_WINDOWS_INSTALLER.md Troubleshooting section
4. Open issue on GitHub with full error output
