#!/usr/bin/env bash
# ==============================================================================
# SFT Windows Installer Build Script (Linux Cross-Compilation)
# Build Windows installer from Linux using cross-compilation tools
# ==============================================================================
# Prerequisites:
# - Rust toolchain with Windows target (rustup target add x86_64-pc-windows-msvc)
# - cargo-xwin (cargo install cargo-xwin) OR wine + mingw
# - Python 3.11+ installed on Linux
# - Inno Setup via Wine (optional, or build on Windows after prep)
# - Internet connection
# ==============================================================================

set -euo pipefail

# Configuration
PYTHON_VERSION="3.11.9"
PYTHON_EMBED_URL="https://www.python.org/ftp/python/${PYTHON_VERSION}/python-${PYTHON_VERSION}-embed-amd64.zip"
VCREDIST_URL="https://aka.ms/vs/17/release/vc_redist.x64.exe"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
INSTALLER_DIR="$SCRIPT_DIR"
OUTPUT_DIR="$INSTALLER_DIR/output"
PYTHON_EMBED_DIR="$INSTALLER_DIR/python-embedded"
SITE_PACKAGES_DIR="$INSTALLER_DIR/site-packages"
ASSETS_DIR="$INSTALLER_DIR/assets"
LAUNCHERS_DIR="$INSTALLER_DIR/launchers"
TARGET_DIR="$PROJECT_ROOT/target"
WHEELS_DIR="$TARGET_DIR/wheels"

COLOR_RESET="\033[0m"
COLOR_CYAN="\033[0;36m"
COLOR_GREEN="\033[0;32m"
COLOR_YELLOW="\033[0;33m"
COLOR_RED="\033[0;31m"

echo -e "${COLOR_CYAN}========================================"
echo -e "SFT Windows Installer Builder (Linux)"
echo -e "========================================${COLOR_RESET}"
echo ""

# Verify prerequisites
check_prerequisites() {
    echo -e "${COLOR_YELLOW}[1/9] Checking prerequisites...${COLOR_RESET}"

    # Check Rust
    if ! command -v rustc &> /dev/null; then
        echo -e "${COLOR_RED}ERROR: Rust toolchain not found. Install from https://rustup.rs/${COLOR_RESET}"
        exit 1
    fi
    echo -e "${COLOR_GREEN}  ✓ Rust: $(rustc --version)${COLOR_RESET}"

    # Check Windows target
    if ! rustup target list --installed | grep -q "x86_64-pc-windows-msvc"; then
        echo -e "${COLOR_YELLOW}  ! Windows MSVC target not found, installing...${COLOR_RESET}"
        rustup target add x86_64-pc-windows-msvc
    fi
    echo -e "${COLOR_GREEN}  ✓ Rust target: x86_64-pc-windows-msvc${COLOR_RESET}"

    # Check cargo-xwin (preferred) or cargo-zigbuild
    if command -v cargo-xwin &> /dev/null; then
        CROSS_COMPILE_TOOL="cargo-xwin"
        echo -e "${COLOR_GREEN}  ✓ Cross-compilation: cargo-xwin${COLOR_RESET}"
    elif command -v cargo-zigbuild &> /dev/null; then
        CROSS_COMPILE_TOOL="cargo-zigbuild"
        echo -e "${COLOR_GREEN}  ✓ Cross-compilation: cargo-zigbuild${COLOR_RESET}"
    else
        echo -e "${COLOR_YELLOW}  ! No cross-compilation tool found${COLOR_RESET}"
        echo -e "${COLOR_YELLOW}    Install cargo-xwin: cargo install cargo-xwin${COLOR_RESET}"
        echo -e "${COLOR_YELLOW}    Or cargo-zigbuild: cargo install cargo-zigbuild${COLOR_RESET}"
        echo -e "${COLOR_YELLOW}    Proceeding with standard cargo (may require wine)${COLOR_RESET}"
        CROSS_COMPILE_TOOL="cargo"
    fi

    # Check Python
    if ! command -v python3 &> /dev/null; then
        echo -e "${COLOR_RED}ERROR: Python 3 not found${COLOR_RESET}"
        exit 1
    fi
    echo -e "${COLOR_GREEN}  ✓ Python: $(python3 --version)${COLOR_RESET}"

    # Check maturin
    if ! command -v maturin &> /dev/null; then
        echo -e "${COLOR_YELLOW}  ! Maturin not found, installing...${COLOR_RESET}"
        pip3 install --user maturin
        export PATH="$HOME/.local/bin:$PATH"
    fi
    echo -e "${COLOR_GREEN}  ✓ Maturin: $(maturin --version)${COLOR_RESET}"

    # Check for download tools
    if ! command -v wget &> /dev/null && ! command -v curl &> /dev/null; then
        echo -e "${COLOR_RED}ERROR: wget or curl required for downloads${COLOR_RESET}"
        exit 1
    fi

    # Check unzip
    if ! command -v unzip &> /dev/null; then
        echo -e "${COLOR_RED}ERROR: unzip required${COLOR_RESET}"
        exit 1
    fi

    echo ""
}

# Build Rust crypto module for Windows
build_rust_module() {
    echo -e "${COLOR_YELLOW}[2/9] Building Rust crypto_accelerator module for Windows...${COLOR_RESET}"

    cd "$PROJECT_ROOT"

    mkdir -p "$WHEELS_DIR"

    echo -e "${COLOR_CYAN}  Cross-compiling with $CROSS_COMPILE_TOOL...${COLOR_RESET}"

    case "$CROSS_COMPILE_TOOL" in
        "cargo-xwin")
            # cargo-xwin is preferred for PyO3 MSVC targets
            maturin build --release --target x86_64-pc-windows-msvc --out "$WHEELS_DIR" \
                --compatibility windows
            ;;
        "cargo-zigbuild")
            # cargo-zigbuild alternative
            maturin build --release --target x86_64-pc-windows-msvc --out "$WHEELS_DIR" \
                --zig --compatibility windows
            ;;
        *)
            # Fallback to standard cargo (requires wine for linking)
            echo -e "${COLOR_YELLOW}  Warning: Using standard cargo, may fail without wine${COLOR_RESET}"
            maturin build --release --target x86_64-pc-windows-msvc --out "$WHEELS_DIR"
            ;;
    esac

    if [ $? -ne 0 ]; then
        echo -e "${COLOR_RED}ERROR: Rust build failed${COLOR_RESET}"
        exit 1
    fi

    echo -e "${COLOR_GREEN}  ✓ Rust module built successfully${COLOR_RESET}"
    echo ""
}

# Download Python embedded distribution
download_python_embedded() {
    echo -e "${COLOR_YELLOW}[3/9] Downloading Python embedded distribution...${COLOR_RESET}"

    rm -rf "$PYTHON_EMBED_DIR"
    mkdir -p "$PYTHON_EMBED_DIR"

    local zip_path="/tmp/python-embedded.zip"

    echo -e "${COLOR_CYAN}  Downloading from: $PYTHON_EMBED_URL${COLOR_RESET}"

    if command -v wget &> /dev/null; then
        wget -q --show-progress -O "$zip_path" "$PYTHON_EMBED_URL"
    else
        curl -L -o "$zip_path" "$PYTHON_EMBED_URL" --progress-bar
    fi

    echo -e "${COLOR_CYAN}  Extracting...${COLOR_RESET}"
    unzip -q "$zip_path" -d "$PYTHON_EMBED_DIR"

    rm "$zip_path"

    echo -e "${COLOR_GREEN}  ✓ Python embedded downloaded and extracted${COLOR_RESET}"
    echo ""
}

# Install Python dependencies to site-packages
install_python_dependencies() {
    echo -e "${COLOR_YELLOW}[4/9] Installing Python dependencies...${COLOR_RESET}"

    rm -rf "$SITE_PACKAGES_DIR"
    mkdir -p "$SITE_PACKAGES_DIR"

    local requirements_path="$PROJECT_ROOT/requirements.txt"

    echo -e "${COLOR_CYAN}  Installing from requirements.txt...${COLOR_RESET}"
    pip3 install --target "$SITE_PACKAGES_DIR" -r "$requirements_path" --no-warn-script-location

    # Remove unnecessary files to reduce size
    echo -e "${COLOR_CYAN}  Cleaning up unnecessary files...${COLOR_RESET}"
    find "$SITE_PACKAGES_DIR" -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
    find "$SITE_PACKAGES_DIR" -type f -name "*.pyc" -delete
    find "$SITE_PACKAGES_DIR" -type f -name "*.pyo" -delete
    find "$SITE_PACKAGES_DIR" -type d -name "*.dist-info" -exec rm -rf {} + 2>/dev/null || true

    echo -e "${COLOR_GREEN}  ✓ Dependencies installed${COLOR_RESET}"
    echo ""
}

# Extract .pyd file from wheel
extract_wheel_module() {
    echo -e "${COLOR_YELLOW}[5/9] Extracting Rust module from wheel...${COLOR_RESET}"

    local wheel_file=$(find "$WHEELS_DIR" -name "crypto_accelerator*.whl" -type f | head -n 1)

    if [ -z "$wheel_file" ]; then
        echo -e "${COLOR_RED}ERROR: Wheel file not found in $WHEELS_DIR${COLOR_RESET}"
        exit 1
    fi

    local temp_extract="/tmp/wheel_extract"
    rm -rf "$temp_extract"
    mkdir -p "$temp_extract"

    echo -e "${COLOR_CYAN}  Extracting wheel: $(basename "$wheel_file")${COLOR_RESET}"
    unzip -q "$wheel_file" -d "$temp_extract"

    # Find .pyd file
    local pyd_file=$(find "$temp_extract" -name "*.pyd" -type f | head -n 1)

    if [ -z "$pyd_file" ]; then
        echo -e "${COLOR_RED}ERROR: .pyd file not found in wheel${COLOR_RESET}"
        exit 1
    fi

    cp "$pyd_file" "$WHEELS_DIR/"

    rm -rf "$temp_extract"

    echo -e "${COLOR_GREEN}  ✓ Extracted: $(basename "$pyd_file")${COLOR_RESET}"
    echo ""
}

# Create launcher batch files
create_launcher_scripts() {
    echo -e "${COLOR_YELLOW}[6/9] Creating launcher scripts...${COLOR_RESET}"

    rm -rf "$LAUNCHERS_DIR"
    mkdir -p "$LAUNCHERS_DIR"

    # Main launcher
    cat > "$LAUNCHERS_DIR/sft.bat" << 'EOF'
@echo off
REM SFT Main Launcher
setlocal
set SCRIPT_DIR=%~dp0
set PYTHON_HOME=%SCRIPT_DIR%python
set PYTHONPATH=%SCRIPT_DIR%;%PYTHON_HOME%\Lib\site-packages
"%PYTHON_HOME%\python.exe" "%SCRIPT_DIR%sft.py" %*
EOF

    # Server launcher
    cat > "$LAUNCHERS_DIR/sft-server.bat" << 'EOF'
@echo off
REM SFT Server Launcher
setlocal
set SCRIPT_DIR=%~dp0
set PYTHON_HOME=%SCRIPT_DIR%python
set PYTHONPATH=%SCRIPT_DIR%;%PYTHON_HOME%\Lib\site-packages
"%PYTHON_HOME%\python.exe" "%SCRIPT_DIR%sft.py" --server %*
EOF

    # Client launcher
    cat > "$LAUNCHERS_DIR/sft-client.bat" << 'EOF'
@echo off
REM SFT Client Launcher
setlocal
set SCRIPT_DIR=%~dp0
set PYTHON_HOME=%SCRIPT_DIR%python
set PYTHONPATH=%SCRIPT_DIR%;%PYTHON_HOME%\Lib\site-packages
"%PYTHON_HOME%\python.exe" "%SCRIPT_DIR%sft.py" --client %*
EOF

    # Ensure DOS line endings (CRLF)
    if command -v unix2dos &> /dev/null; then
        unix2dos "$LAUNCHERS_DIR"/*.bat 2>/dev/null || true
    fi

    echo -e "${COLOR_GREEN}  ✓ Launcher scripts created${COLOR_RESET}"
    echo ""
}

# Create or verify assets (icon, etc.)
prepare_assets() {
    echo -e "${COLOR_YELLOW}[7/9] Preparing assets...${COLOR_RESET}"

    mkdir -p "$ASSETS_DIR"

    local icon_path="$ASSETS_DIR/sft.ico"

    if [ ! -f "$icon_path" ]; then
        echo -e "${COLOR_YELLOW}  ! Warning: sft.ico not found${COLOR_RESET}"
        echo -e "${COLOR_YELLOW}    Creating placeholder at $icon_path${COLOR_RESET}"
        echo -e "${COLOR_YELLOW}    Replace with actual .ico file before final build${COLOR_RESET}"
        echo "PLACEHOLDER" > "$icon_path"
    fi

    echo -e "${COLOR_GREEN}  ✓ Assets ready${COLOR_RESET}"
    echo ""
}

# Download VC++ Redistributable (optional, bundled in installer)
download_vcredist() {
    echo -e "${COLOR_YELLOW}[8/9] Preparing Visual C++ Redistributable...${COLOR_RESET}"

    local vcredist_path="$INSTALLER_DIR/vc_redist.x64.exe"

    if [ -f "$vcredist_path" ]; then
        echo -e "${COLOR_GREEN}  ✓ VC++ Redistributable already present${COLOR_RESET}"
    else
        echo -e "${COLOR_CYAN}  Downloading VC++ Redistributable...${COLOR_RESET}"

        if command -v wget &> /dev/null; then
            wget -q --show-progress -O "$vcredist_path" "$VCREDIST_URL"
        else
            curl -L -o "$vcredist_path" "$VCREDIST_URL" --progress-bar
        fi

        echo -e "${COLOR_GREEN}  ✓ VC++ Redistributable downloaded${COLOR_RESET}"
    fi

    echo ""
}

# Compile installer with Inno Setup (via Wine or manual on Windows)
compile_installer() {
    echo -e "${COLOR_YELLOW}[9/9] Preparing for Inno Setup compilation...${COLOR_RESET}"

    local iss_script="$INSTALLER_DIR/sft-setup.iss"

    if [ ! -f "$iss_script" ]; then
        echo -e "${COLOR_RED}ERROR: Inno Setup script not found: $iss_script${COLOR_RESET}"
        exit 1
    fi

    mkdir -p "$OUTPUT_DIR"

    # Check if Wine and Inno Setup are available
    if command -v wine &> /dev/null && [ -f "$HOME/.wine/drive_c/Program Files (x86)/Inno Setup 6/ISCC.exe" ]; then
        echo -e "${COLOR_CYAN}  Compiling with Inno Setup via Wine...${COLOR_RESET}"
        wine "$HOME/.wine/drive_c/Program Files (x86)/Inno Setup 6/ISCC.exe" "$iss_script"

        if [ $? -eq 0 ]; then
            echo -e "${COLOR_GREEN}  ✓ Installer compiled successfully${COLOR_RESET}"

            local output_exe=$(find "$OUTPUT_DIR" -name "SFT-Setup-*.exe" -type f | head -n 1)

            if [ -n "$output_exe" ]; then
                echo ""
                echo -e "${COLOR_GREEN}========================================"
                echo -e "SUCCESS!"
                echo -e "========================================${COLOR_RESET}"
                echo -e "${COLOR_CYAN}Installer created: $output_exe${COLOR_RESET}"
                echo -e "${COLOR_CYAN}Size: $(du -h "$output_exe" | cut -f1)${COLOR_RESET}"
                echo ""
            fi
        else
            echo -e "${COLOR_RED}ERROR: Inno Setup compilation failed${COLOR_RESET}"
            exit 1
        fi
    else
        echo -e "${COLOR_YELLOW}  ! Inno Setup via Wine not available${COLOR_RESET}"
        echo ""
        echo -e "${COLOR_GREEN}========================================"
        echo -e "PREPARATION COMPLETE"
        echo -e "========================================${COLOR_RESET}"
        echo -e "${COLOR_CYAN}All files prepared for Windows installer build.${COLOR_RESET}"
        echo ""
        echo -e "${COLOR_YELLOW}To complete the build on Windows:${COLOR_RESET}"
        echo -e "  1. Transfer the entire installer/ directory to a Windows machine"
        echo -e "  2. Install Inno Setup 6.x from https://jrsoftware.org/isdl.php"
        echo -e "  3. Right-click sft-setup.iss and select 'Compile'"
        echo -e "  OR run: build-installer.ps1 on Windows"
        echo ""
    fi
}

# Main execution
main() {
    check_prerequisites
    build_rust_module
    download_python_embedded
    install_python_dependencies
    extract_wheel_module
    create_launcher_scripts
    prepare_assets
    download_vcredist
    compile_installer

    echo -e "${COLOR_GREEN}Build process completed!${COLOR_RESET}"
}

main "$@"
