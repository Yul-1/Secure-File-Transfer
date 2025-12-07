# ==============================================================================
# SFT Windows Installer Build Script (PowerShell)
# Native build on Windows for creating the complete installer
# ==============================================================================
# Prerequisites:
# - Rust toolchain (rustup + MSVC target)
# - Python 3.11+ installed
# - Inno Setup 6.x installed
# - Internet connection (for downloading Python embedded)
# ==============================================================================

param(
    [switch]$SkipRustBuild = $false,
    [switch]$SkipDependencies = $false,
    [switch]$SkipPythonDownload = $false,
    [switch]$Verbose = $false
)

$ErrorActionPreference = "Stop"

# Configuration
$PYTHON_VERSION = "3.11.9"
$PYTHON_EMBED_URL = "https://www.python.org/ftp/python/$PYTHON_VERSION/python-$PYTHON_VERSION-embed-amd64.zip"
$VCREDIST_URL = "https://aka.ms/vs/17/release/vc_redist.x64.exe"
$INNO_SETUP_PATH = "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe"
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$PROJECT_ROOT = Split-Path -Parent $SCRIPT_DIR
$INSTALLER_DIR = Join-Path $SCRIPT_DIR "."
$OUTPUT_DIR = Join-Path $INSTALLER_DIR "output"
$PYTHON_EMBED_DIR = Join-Path $INSTALLER_DIR "python-embedded"
$SITE_PACKAGES_DIR = Join-Path $INSTALLER_DIR "site-packages"
$ASSETS_DIR = Join-Path $INSTALLER_DIR "assets"
$LAUNCHERS_DIR = Join-Path $INSTALLER_DIR "launchers"
$TARGET_DIR = Join-Path $PROJECT_ROOT "target"
$WHEELS_DIR = Join-Path $TARGET_DIR "wheels"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "SFT Windows Installer Builder" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Verify prerequisites
function Test-Prerequisites {
    Write-Host "[1/9] Checking prerequisites..." -ForegroundColor Yellow

    # Check Rust
    if (-not (Get-Command rustc -ErrorAction SilentlyContinue)) {
        Write-Error "Rust toolchain not found. Install from https://rustup.rs/"
    }
    Write-Host "  ✓ Rust: $(rustc --version)" -ForegroundColor Green

    # Check Python
    if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
        Write-Error "Python not found. Install Python 3.11+ from https://www.python.org/"
    }
    $pyVersion = python --version
    Write-Host "  ✓ Python: $pyVersion" -ForegroundColor Green

    # Check maturin
    if (-not (Get-Command maturin -ErrorAction SilentlyContinue)) {
        Write-Host "  ! Maturin not found, installing..." -ForegroundColor Yellow
        pip install maturin
    }
    Write-Host "  ✓ Maturin: $(maturin --version)" -ForegroundColor Green

    # Check Inno Setup
    if (-not (Test-Path $INNO_SETUP_PATH)) {
        Write-Error "Inno Setup not found at $INNO_SETUP_PATH. Install from https://jrsoftware.org/isdl.php"
    }
    Write-Host "  ✓ Inno Setup: Found" -ForegroundColor Green

    Write-Host ""
}

# Build Rust crypto module for Windows
function Build-RustModule {
    if ($SkipRustBuild) {
        Write-Host "[2/9] Skipping Rust build (--SkipRustBuild)" -ForegroundColor Yellow
        return
    }

    Write-Host "[2/9] Building Rust crypto_accelerator module..." -ForegroundColor Yellow

    Push-Location $PROJECT_ROOT

    try {
        # Ensure target is set to MSVC (required by PyO3)
        $env:RUSTFLAGS = "-C target-feature=+crt-static"

        # Build with maturin for Windows
        Write-Host "  Building with maturin (release mode)..." -ForegroundColor Cyan
        maturin build --release --target x86_64-pc-windows-msvc --out $WHEELS_DIR

        if ($LASTEXITCODE -ne 0) {
            Write-Error "Rust build failed"
        }

        Write-Host "  ✓ Rust module built successfully" -ForegroundColor Green
    }
    finally {
        Pop-Location
    }

    Write-Host ""
}

# Download Python embedded distribution
function Get-PythonEmbedded {
    if ($SkipPythonDownload -and (Test-Path $PYTHON_EMBED_DIR)) {
        Write-Host "[3/9] Skipping Python download (--SkipPythonDownload)" -ForegroundColor Yellow
        return
    }

    Write-Host "[3/9] Downloading Python embedded distribution..." -ForegroundColor Yellow

    if (Test-Path $PYTHON_EMBED_DIR) {
        Remove-Item -Recurse -Force $PYTHON_EMBED_DIR
    }

    New-Item -ItemType Directory -Force -Path $PYTHON_EMBED_DIR | Out-Null

    $zipPath = Join-Path $env:TEMP "python-embedded.zip"

    Write-Host "  Downloading from: $PYTHON_EMBED_URL" -ForegroundColor Cyan
    Invoke-WebRequest -Uri $PYTHON_EMBED_URL -OutFile $zipPath

    Write-Host "  Extracting..." -ForegroundColor Cyan
    Expand-Archive -Path $zipPath -DestinationPath $PYTHON_EMBED_DIR -Force

    Remove-Item $zipPath

    Write-Host "  ✓ Python embedded downloaded and extracted" -ForegroundColor Green
    Write-Host ""
}

# Install Python dependencies to site-packages
function Install-PythonDependencies {
    if ($SkipDependencies -and (Test-Path $SITE_PACKAGES_DIR)) {
        Write-Host "[4/9] Skipping dependency installation (--SkipDependencies)" -ForegroundColor Yellow
        return
    }

    Write-Host "[4/9] Installing Python dependencies..." -ForegroundColor Yellow

    if (Test-Path $SITE_PACKAGES_DIR) {
        Remove-Item -Recurse -Force $SITE_PACKAGES_DIR
    }

    New-Item -ItemType Directory -Force -Path $SITE_PACKAGES_DIR | Out-Null

    $requirementsPath = Join-Path $PROJECT_ROOT "requirements.txt"

    Write-Host "  Installing from requirements.txt..." -ForegroundColor Cyan
    pip install --target $SITE_PACKAGES_DIR -r $requirementsPath --no-warn-script-location

    # Remove unnecessary files to reduce size
    Write-Host "  Cleaning up unnecessary files..." -ForegroundColor Cyan
    Get-ChildItem -Path $SITE_PACKAGES_DIR -Recurse -Include "__pycache__","*.pyc","*.pyo" | Remove-Item -Recurse -Force
    Get-ChildItem -Path $SITE_PACKAGES_DIR -Recurse -Filter "*.dist-info" | Remove-Item -Recurse -Force

    Write-Host "  ✓ Dependencies installed" -ForegroundColor Green
    Write-Host ""
}

# Extract .pyd file from wheel
function Extract-WheelModule {
    Write-Host "[5/9] Extracting Rust module from wheel..." -ForegroundColor Yellow

    $wheelFile = Get-ChildItem -Path $WHEELS_DIR -Filter "crypto_accelerator*.whl" | Select-Object -First 1

    if (-not $wheelFile) {
        Write-Error "Wheel file not found in $WHEELS_DIR"
    }

    $tempExtract = Join-Path $env:TEMP "wheel_extract"
    if (Test-Path $tempExtract) {
        Remove-Item -Recurse -Force $tempExtract
    }

    New-Item -ItemType Directory -Force -Path $tempExtract | Out-Null

    Write-Host "  Extracting wheel: $($wheelFile.Name)" -ForegroundColor Cyan
    Expand-Archive -Path $wheelFile.FullName -DestinationPath $tempExtract -Force

    # Find .pyd file
    $pydFile = Get-ChildItem -Path $tempExtract -Recurse -Filter "*.pyd" | Select-Object -First 1

    if (-not $pydFile) {
        Write-Error ".pyd file not found in wheel"
    }

    # Ensure target directory exists
    $pydTargetDir = Join-Path $WHEELS_DIR ""
    Copy-Item -Path $pydFile.FullName -Destination $pydTargetDir -Force

    Remove-Item -Recurse -Force $tempExtract

    Write-Host "  ✓ Extracted: $($pydFile.Name)" -ForegroundColor Green
    Write-Host ""
}

# Create launcher batch files
function New-LauncherScripts {
    Write-Host "[6/9] Creating launcher scripts..." -ForegroundColor Yellow

    if (Test-Path $LAUNCHERS_DIR) {
        Remove-Item -Recurse -Force $LAUNCHERS_DIR
    }

    New-Item -ItemType Directory -Force -Path $LAUNCHERS_DIR | Out-Null

    # Main launcher
    $sftBat = @"
@echo off
REM SFT Main Launcher
setlocal
set SCRIPT_DIR=%~dp0
set PYTHON_HOME=%SCRIPT_DIR%python
set PYTHONPATH=%SCRIPT_DIR%;%PYTHON_HOME%\Lib\site-packages
"%PYTHON_HOME%\python.exe" "%SCRIPT_DIR%sft.py" %*
"@
    $sftBat | Out-File -FilePath (Join-Path $LAUNCHERS_DIR "sft.bat") -Encoding ASCII

    # Server launcher
    $serverBat = @"
@echo off
REM SFT Server Launcher
setlocal
set SCRIPT_DIR=%~dp0
set PYTHON_HOME=%SCRIPT_DIR%python
set PYTHONPATH=%SCRIPT_DIR%;%PYTHON_HOME%\Lib\site-packages
"%PYTHON_HOME%\python.exe" "%SCRIPT_DIR%sft.py" --server %*
"@
    $serverBat | Out-File -FilePath (Join-Path $LAUNCHERS_DIR "sft-server.bat") -Encoding ASCII

    # Client launcher
    $clientBat = @"
@echo off
REM SFT Client Launcher
setlocal
set SCRIPT_DIR=%~dp0
set PYTHON_HOME=%SCRIPT_DIR%python
set PYTHONPATH=%SCRIPT_DIR%;%PYTHON_HOME%\Lib\site-packages
"%PYTHON_HOME%\python.exe" "%SCRIPT_DIR%sft.py" --client %*
"@
    $clientBat | Out-File -FilePath (Join-Path $LAUNCHERS_DIR "sft-client.bat") -Encoding ASCII

    Write-Host "  ✓ Launcher scripts created" -ForegroundColor Green
    Write-Host ""
}

# Create or verify assets (icon, etc.)
function Initialize-Assets {
    Write-Host "[7/9] Preparing assets..." -ForegroundColor Yellow

    if (-not (Test-Path $ASSETS_DIR)) {
        New-Item -ItemType Directory -Force -Path $ASSETS_DIR | Out-Null
    }

    $iconPath = Join-Path $ASSETS_DIR "sft.ico"

    # Create placeholder icon if not exists (user should replace with actual icon)
    if (-not (Test-Path $iconPath)) {
        Write-Host "  ! Warning: sft.ico not found, creating placeholder" -ForegroundColor Yellow
        Write-Host "    Replace $iconPath with actual icon before final build" -ForegroundColor Yellow
        # Cannot create .ico programmatically easily, just warn
        "PLACEHOLDER" | Out-File -FilePath $iconPath -Encoding ASCII
    }

    Write-Host "  ✓ Assets ready" -ForegroundColor Green
    Write-Host ""
}

# Download VC++ Redistributable (optional, bundled in installer)
function Get-VCRedist {
    Write-Host "[8/9] Preparing Visual C++ Redistributable..." -ForegroundColor Yellow

    $vcRedistPath = Join-Path $INSTALLER_DIR "vc_redist.x64.exe"

    if (Test-Path $vcRedistPath) {
        Write-Host "  ✓ VC++ Redistributable already present" -ForegroundColor Green
    } else {
        Write-Host "  Downloading VC++ Redistributable..." -ForegroundColor Cyan
        Invoke-WebRequest -Uri $VCREDIST_URL -OutFile $vcRedistPath
        Write-Host "  ✓ VC++ Redistributable downloaded" -ForegroundColor Green
    }

    Write-Host ""
}

# Compile installer with Inno Setup
function Build-Installer {
    Write-Host "[9/9] Compiling installer with Inno Setup..." -ForegroundColor Yellow

    $issScript = Join-Path $INSTALLER_DIR "sft-setup.iss"

    if (-not (Test-Path $issScript)) {
        Write-Error "Inno Setup script not found: $issScript"
    }

    Write-Host "  Compiling: $issScript" -ForegroundColor Cyan

    & $INNO_SETUP_PATH $issScript

    if ($LASTEXITCODE -ne 0) {
        Write-Error "Inno Setup compilation failed"
    }

    Write-Host "  ✓ Installer compiled successfully" -ForegroundColor Green
    Write-Host ""

    $outputExe = Get-ChildItem -Path $OUTPUT_DIR -Filter "SFT-Setup-*.exe" | Select-Object -First 1

    if ($outputExe) {
        Write-Host "========================================" -ForegroundColor Green
        Write-Host "SUCCESS!" -ForegroundColor Green
        Write-Host "========================================" -ForegroundColor Green
        Write-Host "Installer created: $($outputExe.FullName)" -ForegroundColor Cyan
        Write-Host "Size: $([math]::Round($outputExe.Length / 1MB, 2)) MB" -ForegroundColor Cyan
        Write-Host ""
    }
}

# Main execution
try {
    Test-Prerequisites
    Build-RustModule
    Get-PythonEmbedded
    Install-PythonDependencies
    Extract-WheelModule
    New-LauncherScripts
    Initialize-Assets
    Get-VCRedist
    Build-Installer

    Write-Host "Build completed successfully!" -ForegroundColor Green
}
catch {
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Red
    Write-Host "BUILD FAILED" -ForegroundColor Red
    Write-Host "========================================" -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
    Write-Host ""
    exit 1
}
