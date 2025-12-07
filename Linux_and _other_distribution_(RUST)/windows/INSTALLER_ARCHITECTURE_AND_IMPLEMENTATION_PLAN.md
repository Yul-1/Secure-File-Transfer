# SFT Windows Installer - Complete Architecture & Implementation Plan

**Document Version:** 1.0
**Date:** 2025-12-07
**Branch:** feature-windows-installer
**Status:** Analysis Complete - Ready for Enhancement Implementation

---

## EXECUTIVE SUMMARY

### Current State Analysis

The Windows installer infrastructure is **90% complete** with a robust foundation already in place. The system uses Inno Setup 6.x to create a single-file .exe installer that packages Python 3.11.9 embedded runtime, pre-compiled Rust crypto module, and all dependencies into a ~50-70MB distributable.

**What Currently Exists:**
- Complete Inno Setup script (`sft-setup.iss`)
- Automated PowerShell build script for native Windows builds
- Cross-compilation Bash script for Linux → Windows builds
- Pre/post installation documentation
- Launcher batch script templates
- Asset and output directory structure

**Critical Gaps Identified:**
1. **Launcher scripts not pre-generated** - Directory exists but .bat files missing
2. **Icon file missing** - Placeholder needed, actual .ico required for production
3. **Build untested** - No evidence of successful compilation
4. **VC++ Redistributable bundling incomplete** - Download logic exists but file not verified
5. **Path configuration** - python311._pth modification logic present but untested

### Recommended Path Forward

**DO NOT redesign.** The architecture is sound. Focus on:
1. Completing missing components (launcher scripts, icon)
2. Testing and validating the build process
3. Hardening security aspects
4. Adding verification and checksumming
5. Documenting the complete build-test-distribute workflow

---

## PART 1: ARCHITECTURAL ANALYSIS

### 1.1 Installer Technology Stack Assessment

**Selected Technology: Inno Setup 6.x**

**Justification (Security-First Analysis):**

| Criterion | Inno Setup | NSIS | WiX | PyInstaller+Wrapper | Verdict |
|-----------|-----------|------|-----|---------------------|---------|
| **Code Signing Support** | Native | Native | Native | External signtool | ✓ Inno/NSIS/WiX |
| **Compression Security** | LZMA2 (audited) | LZMA/zlib | CAB (legacy) | zlib | ✓ Inno Setup |
| **Script Audit Trail** | Pascal (readable) | Assembly-like | XML (verbose) | N/A | ✓ Inno Setup |
| **AV False Positive Rate** | Low | Medium | Low | HIGH | ✓ Inno/WiX |
| **Embedded Python Support** | Excellent | Good | Complex | Native | ✓ Inno Setup |
| **Uninstaller Integrity** | Automatic | Manual | MSI standard | Manual | ✓ Inno/WiX |
| **Learning Curve** | Low | Medium | High | Low | ✓ Inno Setup |
| **Windows 8-11 Compat** | Full | Full | Full | Partial | ✓ All |
| **Open Source** | Yes | Yes | Yes | Yes | ✓ All |

**Decision: Inno Setup is CORRECT for this project.**

**Rationale:**
- Security-critical applications require auditable installer scripts
- Pascal-like syntax is more maintainable than NSIS assembly
- Native Python embedded support reduces attack surface vs. PyInstaller bundling
- Low AV false positive rate critical for security software distribution
- Mature, actively maintained (2025 release cycle)

### 1.2 Component Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                  SFT-Setup-1.8.0-win64.exe                      │
│                    (Single Distributable)                        │
└────────────────────────┬────────────────────────────────────────┘
                         │
         ┌───────────────┼───────────────┐
         │               │               │
    ┌────▼────┐    ┌────▼────┐    ┌────▼────┐
    │ Python  │    │  Rust   │    │  SFT    │
    │ 3.11.9  │    │ Crypto  │    │  App    │
    │Embedded │    │ Module  │    │ Files   │
    └────┬────┘    └────┬────┘    └────┬────┘
         │              │              │
         └──────────────┴──────────────┘
                        │
              ┌─────────▼─────────┐
              │  Installation     │
              │  C:\Program Files\SFT\ │
              └───────────────────┘
                        │
         ┌──────────────┼──────────────┐
         │              │              │
    ┌────▼────┐    ┌───▼────┐    ┌───▼────┐
    │Shortcuts│    │ Batch  │    │Registry│
    │(Start/  │    │Launcher│    │ Uninst │
    │Desktop) │    │Scripts │    │ Entry  │
    └─────────┘    └────────┘    └────────┘
```

**Component Manifest:**

1. **Python Embedded Runtime** (30 MB)
   - Source: `https://www.python.org/ftp/python/3.11.9/python-3.11.9-embed-amd64.zip`
   - SHA256: Required for supply chain security (NOT CURRENTLY VERIFIED)
   - Contents: python311.dll, python.exe, stdlib in python311.zip
   - Modified: python311._pth (adds site-packages path)

2. **Rust Crypto Module** (2-4 MB)
   - Built: `crypto_accelerator.cp311-win_amd64.pyd`
   - Compiler: maturin + MSVC linker
   - Target: x86_64-pc-windows-msvc
   - Dependencies: Statically linked (ring, aes-gcm, ed25519-dalek)

3. **Python Dependencies** (15-25 MB)
   - cryptography (OpenSSL bindings)
   - PyNaCl (libsodium bindings)
   - jsonschema, PySocks, attrs, etc.
   - Pre-installed to avoid pip on target system

4. **SFT Application** (< 1 MB)
   - sft.py (1851 lines - protocol implementation)
   - python_wrapper.py (391 lines - crypto wrapper)
   - README.md, LICENSE, requirements.txt

5. **Launcher Scripts** (< 10 KB)
   - sft.bat (general purpose)
   - sft-server.bat (--server mode)
   - sft-client.bat (--client mode)

6. **VC++ Redistributable** (Conditional)
   - Downloaded: vc_redist.x64.exe (~24 MB)
   - Installed only if registry check fails
   - Required by Rust-compiled .pyd

### 1.3 Build Process Flow

```
┌────────────────────────────────────────────────────────────────┐
│ Step 1: Prerequisites Check                                    │
│ ✓ Rust (rustc, cargo, maturin)                                │
│ ✓ Python 3.11+ (for build host)                               │
│ ✓ Inno Setup 6.x (ISCC.exe)                                   │
│ ✓ Internet connectivity                                        │
└────────────┬───────────────────────────────────────────────────┘
             │
┌────────────▼───────────────────────────────────────────────────┐
│ Step 2: Compile Rust Module                                    │
│ $ maturin build --release --target x86_64-pc-windows-msvc     │
│ Output: target/wheels/crypto_accelerator-1.8.0-*.whl          │
│ Security: Static linking, strip symbols, LTO optimization     │
└────────────┬───────────────────────────────────────────────────┘
             │
┌────────────▼───────────────────────────────────────────────────┐
│ Step 3: Download Python Embedded                               │
│ Source: python.org/ftp/python/3.11.9/...                      │
│ Extract: installer/python-embedded/                            │
│ TODO: Verify SHA256 checksum (NOT CURRENTLY DONE)             │
└────────────┬───────────────────────────────────────────────────┘
             │
┌────────────▼───────────────────────────────────────────────────┐
│ Step 4: Install Python Dependencies                            │
│ $ pip install --target installer/site-packages -r requirements │
│ Cleanup: Remove __pycache__, *.pyc, .dist-info                │
│ Security: Pinned versions in requirements.txt                  │
└────────────┬───────────────────────────────────────────────────┘
             │
┌────────────▼───────────────────────────────────────────────────┐
│ Step 5: Extract .pyd from Wheel                                │
│ Unzip wheel → Find crypto_accelerator.*.pyd                   │
│ Copy to: target/wheels/ (for Inno Setup [Files] section)      │
└────────────┬───────────────────────────────────────────────────┘
             │
┌────────────▼───────────────────────────────────────────────────┐
│ Step 6: Generate Launcher Scripts (MISSING - NEEDS IMPL)       │
│ Create: installer/launchers/sft.bat                           │
│ Create: installer/launchers/sft-server.bat                    │
│ Create: installer/launchers/sft-client.bat                    │
└────────────┬───────────────────────────────────────────────────┘
             │
┌────────────▼───────────────────────────────────────────────────┐
│ Step 7: Prepare Assets (INCOMPLETE - ICON MISSING)             │
│ Verify: installer/assets/sft.ico                              │
│ TODO: Create actual icon (current: placeholder text file)     │
└────────────┬───────────────────────────────────────────────────┘
             │
┌────────────▼───────────────────────────────────────────────────┐
│ Step 8: Download VC++ Redistributable                          │
│ URL: https://aka.ms/vs/17/release/vc_redist.x64.exe           │
│ Saved: installer/vc_redist.x64.exe                            │
│ Used by: Inno Setup [Run] section (conditional install)       │
└────────────┬───────────────────────────────────────────────────┘
             │
┌────────────▼───────────────────────────────────────────────────┐
│ Step 9: Compile with Inno Setup                                │
│ $ ISCC.exe installer/sft-setup.iss                            │
│ Output: installer/output/SFT-Setup-1.8.0-win64.exe            │
│ Size: ~50-70 MB (LZMA2 ultra64 compression)                   │
└────────────┬───────────────────────────────────────────────────┘
             │
┌────────────▼───────────────────────────────────────────────────┐
│ Step 10: Post-Build (NOT IMPLEMENTED)                          │
│ TODO: Generate SHA256 checksum                                │
│ TODO: Code signing (if certificate available)                 │
│ TODO: Smoke test on clean Windows VM                          │
└────────────────────────────────────────────────────────────────┘
```

---

## PART 2: SECURITY ANALYSIS

### 2.1 Threat Model for Installer Distribution

| Threat | Attack Vector | Mitigation Status | Priority |
|--------|--------------|-------------------|----------|
| **Supply Chain Attack** | Compromised Python download | INCOMPLETE - No checksum verification | **P0** |
| **Supply Chain Attack** | Compromised pip packages | PARTIAL - Pinned versions, no hash verification | **P0** |
| **Man-in-the-Middle** | HTTP download interception | MITIGATED - HTTPS enforced | P1 |
| **Code Injection** | Modified installer .exe | INCOMPLETE - No code signing | **P0** |
| **Trojan Horse** | Malicious .pyd replacement | MITIGATED - Built from source | P1 |
| **Privilege Escalation** | Installer overwrites system files | MITIGATED - Admin required, isolated install dir | P2 |
| **Uninstaller Residue** | Leftover sensitive data | PARTIAL - Logs deleted, keys in memory only | P1 |
| **DLL Hijacking** | Malicious python311.dll | MITIGATED - Embedded Python, explicit paths | P2 |
| **AV False Positive** | Rust .pyd flagged as malware | RISK - No signing, new binary format | P1 |

**Critical Security Gaps:**

1. **No Python Embedded Checksum Verification** (P0)
   ```powershell
   # Current: Just downloads
   Invoke-WebRequest -Uri $PYTHON_EMBED_URL -OutFile $zipPath

   # Required: Verify integrity
   $expectedHash = "KNOWN_SHA256_FOR_PYTHON_3.11.9"
   $actualHash = (Get-FileHash $zipPath -Algorithm SHA256).Hash
   if ($actualHash -ne $expectedHash) { throw "Checksum mismatch!" }
   ```

2. **No pip Package Hash Verification** (P0)
   ```bash
   # Current: requirements.txt
   cryptography==46.0.3

   # Required: Hash-pinned
   cryptography==46.0.3 --hash=sha256:abc123...
   ```

3. **No Code Signing** (P0)
   - Unsigned installer triggers SmartScreen warnings
   - Users cannot verify authenticity
   - AV software more likely to flag as suspicious

4. **No Installer Checksum Publication** (P1)
   - Users have no way to verify download integrity
   - MITM attacks undetectable

### 2.2 Runtime Security Analysis

**Embedded Python Isolation:**
```
✓ SECURE: Dedicated python311._pth prevents PATH pollution
✓ SECURE: No system Python modification
✓ SECURE: Explicit PYTHONPATH in launcher scripts
✗ RISK: python311._pth modification in [Code] section untested
```

**Memory Safety:**
```
✓ SECURE: Rust module uses zeroize for key material
✓ SECURE: Python wrapper calls _clear_memory() on bytearrays
✓ SECURE: No persistent key storage
✗ RISK: Python GC may leave key copies in memory (language limitation)
```

**Network Security:**
```
✓ SECURE: TLS 1.2+ via cryptography library
✓ SECURE: ECDH key exchange (X25519)
✓ SECURE: Ed25519 signatures
✓ SECURE: AES-256-GCM authenticated encryption
✗ RISK: Installer downloads over HTTPS but no cert pinning
```

### 2.3 Build Environment Security

**Windows Native Build:**
- Requires Visual Studio Build Tools (large attack surface)
- Rust toolchain (trusted, but large dependency tree)
- Network access during build (pip, Python download)
- **Recommendation:** Use isolated build VM, snapshot before build

**Linux Cross-Compilation:**
- cargo-xwin adds cross-compilation dependencies
- Wine for Inno Setup (potential vulnerability)
- **Recommendation:** Preferred for reproducible builds, Docker container

---

## PART 3: IMPLEMENTATION PLAN

### 3.1 Critical Path Items (Must Complete Before First Release)

#### Task 1: Generate Launcher Scripts (P0)
**Status:** Directory exists, files missing
**Location:** `windows/installer/launchers/`
**Action Required:**

```batch
# File: sft.bat
@echo off
setlocal
set SCRIPT_DIR=%~dp0
set PYTHON_HOME=%SCRIPT_DIR%python
set PYTHONPATH=%SCRIPT_DIR%;%PYTHON_HOME%\Lib\site-packages
"%PYTHON_HOME%\python.exe" "%SCRIPT_DIR%sft.py" %*
```

```batch
# File: sft-server.bat
@echo off
setlocal
set SCRIPT_DIR=%~dp0
set PYTHON_HOME=%SCRIPT_DIR%python
set PYTHONPATH=%SCRIPT_DIR%;%PYTHON_HOME%\Lib\site-packages
"%PYTHON_HOME%\python.exe" "%SCRIPT_DIR%sft.py" --mode server %*
```

```batch
# File: sft-client.bat
@echo off
setlocal
set SCRIPT_DIR=%~dp0
set PYTHON_HOME=%SCRIPT_DIR%python
set PYTHONPATH=%SCRIPT_DIR%;%PYTHON_HOME%\Lib\site-packages
"%PYTHON_HOME%\python.exe" "%SCRIPT_DIR%sft.py" --mode client %*
```

**Build Script Integration:**
- Current PowerShell script has `New-LauncherScripts` function (lines 203-250)
- Function creates files but writes to `$LAUNCHERS_DIR` (correct)
- **ISSUE:** Files created during build, not committed to repo
- **DECISION:** Keep as build-time generation (correct approach)

#### Task 2: Create Application Icon (P0)
**Status:** Placeholder text file exists
**Location:** `windows/installer/assets/sft.ico`
**Action Required:**

1. Design 256x256 icon representing SFT (shield + lock + network motif)
2. Convert to .ico with multiple resolutions (16x16, 32x32, 48x48, 256x256)
3. Replace placeholder at `windows/installer/assets/sft.ico`

**Tools:**
- GIMP (free, .ico export plugin)
- ImageMagick: `convert -resize 256x256 sft.png sft.ico`
- Online: favicon.io, cloudconvert.com

**Temporary Workaround:**
- Extract icon from python.exe: `ResourceHacker.exe` (Windows)
- Use generic padlock icon from Windows system32

#### Task 3: Implement Checksum Verification (P0)
**Location:** `windows/installer/build-installer.ps1`
**Modification:**

```powershell
# After line 125 (Invoke-WebRequest)
$PYTHON_EMBED_SHA256 = "VERIFY_FROM_PYTHON_ORG"  # TODO: Get official hash

$actualHash = (Get-FileHash $zipPath -Algorithm SHA256).Hash.ToLower()
if ($actualHash -ne $PYTHON_EMBED_SHA256.ToLower()) {
    Write-Error "Python embedded checksum mismatch! Expected: $PYTHON_EMBED_SHA256, Got: $actualHash"
    Remove-Item $zipPath
    exit 1
}
Write-Host "  ✓ Checksum verified" -ForegroundColor Green
```

**Hash Source:** https://www.python.org/downloads/release/python-3119/
Look for "MD5 Sum" / "SHA256 Sum" section

#### Task 4: Add pip Hash Verification (P0)
**Location:** `requirements.txt`
**Action:**

```bash
# Generate hashes
pip hash cryptography==46.0.3 > requirements-hashes.txt
pip hash PyNaCl==1.5.0 >> requirements-hashes.txt
# ... for all packages

# Update requirements.txt
cryptography==46.0.3 --hash=sha256:abc123...
PyNaCl==1.5.0 --hash=sha256:def456...
```

**Build Script Update:**
```powershell
# Line 154
pip install --target $SITE_PACKAGES_DIR -r $requirementsPath --require-hashes --no-warn-script-location
```

#### Task 5: Post-Build Checksum Generation (P1)
**Location:** New script: `windows/installer/generate-checksums.ps1`

```powershell
$installerExe = Get-ChildItem -Path "installer/output" -Filter "SFT-Setup-*.exe" | Select-Object -First 1

if ($installerExe) {
    $sha256 = (Get-FileHash $installerExe.FullName -Algorithm SHA256).Hash
    $sha512 = (Get-FileHash $installerExe.FullName -Algorithm SHA512).Hash

    $checksumFile = "$($installerExe.FullName).checksums.txt"

    @"
SFT Windows Installer Checksums
================================
File: $($installerExe.Name)
Size: $($installerExe.Length) bytes
Date: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")

SHA256: $sha256
SHA512: $sha512

Verification Instructions:
--------------------------
PowerShell:
  Get-FileHash $($installerExe.Name) -Algorithm SHA256

Linux/macOS:
  sha256sum $($installerExe.Name)
"@ | Out-File -FilePath $checksumFile -Encoding UTF8

    Write-Host "Checksums written to: $checksumFile"
}
```

### 3.2 Enhanced Features (Post-MVP)

#### Feature 1: Code Signing Support
**Priority:** P1 (Required for production distribution)
**Cost:** $200-500/year for standard code signing cert, $400-1200/year for EV cert
**Implementation:**

1. Obtain certificate from DigiCert, Sectigo, or GlobalSign
2. Install cert on build machine
3. Update `sft-setup.iss`:
   ```pascal
   SignTool=signtool sign /f "cert.pfx" /p "password" /tr http://timestamp.digicert.com /td sha256 /fd sha256 $f
   SignedUninstaller=yes
   ```

4. Add timestamping (allows signature to remain valid after cert expires)

**Benefits:**
- Eliminates SmartScreen warnings
- Builds user trust
- Required by enterprise deployment policies
- Reduces AV false positives

#### Feature 2: Silent Installation Support
**Priority:** P2 (For enterprise deployment)
**Implementation:**

Inno Setup already supports:
```batch
SFT-Setup-1.8.0-win64.exe /SILENT /DIR="C:\CustomPath"
SFT-Setup-1.8.0-win64.exe /VERYSILENT /SUPPRESSMSGBOXES
```

Add to documentation and create Group Policy deployment guide.

#### Feature 3: Automatic Update Checker
**Priority:** P2
**Implementation:**

Add version check to sft.py:
```python
def check_for_updates():
    try:
        response = requests.get("https://api.github.com/repos/yourusername/SFT/releases/latest", timeout=5)
        latest_version = response.json()["tag_name"].lstrip("v")
        if version.parse(latest_version) > version.parse(CURRENT_VERSION):
            logger.info(f"Update available: {latest_version} (current: {CURRENT_VERSION})")
    except:
        pass
```

Call on startup (non-blocking, timeout=5s).

#### Feature 4: Uninstaller Security Audit
**Priority:** P2
**Action:** Test uninstallation on various Windows versions

```powershell
# Test script
Install-SFT
# Create some files in installation directory
New-Item "C:\Program Files\SFT\test.log"
# Uninstall
Uninstall-SFT
# Verify cleanup
Test-Path "C:\Program Files\SFT\" # Should be False
```

Ensure Inno Setup `[UninstallDelete]` section removes all residual files.

### 3.3 Testing & Validation Plan

#### Build Testing (Before First Installer Creation)

**Test 1: Prerequisites Verification**
```powershell
# Run on clean Windows VM
.\installer\build-installer.ps1 -WhatIf
# Should fail with clear error messages for missing components
```

**Test 2: Incremental Build**
```powershell
# First build
.\installer\build-installer.ps1
# Modify sft.py
# Rebuild (should skip Rust compilation)
.\installer\build-installer.ps1 -SkipRustBuild
# Verify .exe updated
```

**Test 3: Cross-Compilation (Linux)**
```bash
# On Ubuntu 22.04 VM
./installer/build-installer-linux.sh
# Should complete up to step 8 (Inno Setup may fail without Wine)
# Transfer to Windows, run step 9 manually
```

#### Installation Testing (After Build Success)

**Test Suite Matrix:**

| OS Version | Install Type | Test Scenario | Expected Result |
|------------|-------------|---------------|-----------------|
| Win 8.1 x64 | Fresh | Default install | Success, all components |
| Win 10 21H2 | Fresh | Custom path | Success, shortcuts work |
| Win 11 23H2 | Fresh | No desktop icon | Success, Start Menu only |
| Win 10 22H2 | Upgrade | Install over 1.7.0 | Success, clean upgrade |
| Win 10 + AV | Fresh | With Defender | No false positives |
| Win 11 Clean | Fresh + Uninstall | Complete cycle | No residual files |

**Test Script Template:**
```powershell
# install-test.ps1
$installerPath = "SFT-Setup-1.8.0-win64.exe"

# Test 1: Silent install
Start-Process $installerPath -ArgumentList "/VERYSILENT /SUPPRESSMSGBOXES" -Wait

# Test 2: Verify installation
if (-not (Test-Path "C:\Program Files\SFT\sft.py")) {
    throw "Installation failed: sft.py not found"
}

# Test 3: Run basic command
$output = & "C:\Program Files\SFT\sft.bat" --version
if ($output -notmatch "1.8.0") {
    throw "Version check failed"
}

# Test 4: Verify Rust module
$output = & "C:\Program Files\SFT\sft.bat" --test-crypto
if ($output -notmatch "Rust acceleration module loaded successfully") {
    throw "Rust module not loaded"
}

# Test 5: Uninstall
$uninstaller = Get-ChildItem "C:\Program Files\SFT" -Filter "unins*.exe" | Select-Object -First 1
Start-Process $uninstaller.FullName -ArgumentList "/VERYSILENT" -Wait

# Test 6: Verify cleanup
if (Test-Path "C:\Program Files\SFT") {
    throw "Uninstaller left residual files"
}

Write-Host "All tests passed!" -ForegroundColor Green
```

#### Functional Testing (Post-Installation)

**Critical Path Tests:**
1. Server Mode: `sft-server.bat --port 5555` → Should bind and listen
2. Client Mode: `sft-client.bat --help` → Should show usage
3. File Transfer: Server + Client on localhost → Successful transfer
4. Crypto Verification: Check logs for "Rust acceleration module loaded successfully"
5. Error Handling: Invalid command → Clear error message, non-zero exit code

### 3.4 Distribution Strategy

#### Pre-Release Checklist

- [ ] All launcher scripts generated and tested
- [ ] Application icon created (production quality)
- [ ] Python embedded checksum verification implemented
- [ ] pip package hashes added to requirements.txt
- [ ] Build tested on Windows 10 and 11
- [ ] Cross-compilation tested on Linux
- [ ] Installer tested on clean VMs (Win 8.1, 10, 11)
- [ ] Functional tests pass (server, client, transfer)
- [ ] Code signing certificate obtained (if available)
- [ ] Installer signed with certificate
- [ ] SHA256/SHA512 checksums generated
- [ ] CHECKSUMS.txt file created
- [ ] Documentation reviewed and updated
- [ ] README.md includes Windows installation instructions
- [ ] GitHub release draft prepared

#### Release Process

1. **Tag Release**
   ```bash
   git tag -a v1.8.0-windows -m "Windows installer release"
   git push origin v1.8.0-windows
   ```

2. **Build Installer**
   ```powershell
   # On dedicated build VM
   .\installer\build-installer.ps1
   # Sign if certificate available
   .\installer\sign-installer.ps1
   # Generate checksums
   .\installer\generate-checksums.ps1
   ```

3. **Create GitHub Release**
   - Upload: `SFT-Setup-1.8.0-win64.exe`
   - Upload: `SFT-Setup-1.8.0-win64.exe.checksums.txt`
   - Include in description:
     ```markdown
     ## Windows Installer

     **File:** SFT-Setup-1.8.0-win64.exe
     **Size:** ~60 MB
     **SHA256:** [from checksums file]

     ### System Requirements
     - Windows 8 or later (x64)
     - 100 MB disk space
     - Administrator privileges for installation

     ### Installation
     1. Download SFT-Setup-1.8.0-win64.exe
     2. Verify checksum (optional but recommended)
     3. Double-click to run installer
     4. Follow installation wizard

     ### Verification
     ```powershell
     Get-FileHash SFT-Setup-1.8.0-win64.exe -Algorithm SHA256
     ```
     ```

4. **Announce Release**
   - Update main README.md with download link
   - Post to project discussions/announcements
   - Update documentation site (if exists)

#### Distribution Channels

**Primary:**
- GitHub Releases (HTTPS, tracked downloads)

**Secondary (Future):**
- Chocolatey package manager (Windows)
- winget (Microsoft Package Manager)
- SourceForge (mirror for non-GitHub users)

**Enterprise:**
- Provide MSI wrapper for Group Policy deployment
- Create silent install documentation
- Offer custom builds with enterprise branding (on request)

---

## PART 4: CURRENT ISSUES & FIXES

### Issue 1: Launcher Scripts Generated at Build Time Only
**Severity:** Low (by design)
**Status:** Intentional

**Analysis:**
The PowerShell script creates launcher .bat files during build (Step 6). This is **correct** because:
- Scripts need to reference installation path (runtime-determined)
- Prevents stale scripts in repo
- Allows customization per build

**Action:** No change needed. Document this behavior.

### Issue 2: Icon File is Placeholder
**Severity:** High (blocks production release)
**Status:** Requires immediate action

**Current State:**
```bash
$ cat windows/installer/assets/sft.ico
PLACEHOLDER
```

**Fix:** Create actual .ico file (see Task 2 above)

### Issue 3: No Checksum Verification
**Severity:** Critical (security risk)
**Status:** Must implement before release

**Fix:** Implement Tasks 3 & 4 from Section 3.1

### Issue 4: Build Scripts Untested
**Severity:** High (unknown if build works)
**Status:** Requires test builds

**Action Plan:**
1. Create Windows 11 VM for native build test
2. Create Ubuntu 22.04 VM for cross-compilation test
3. Execute full build process
4. Document any errors encountered
5. Update build scripts with fixes
6. Re-test until successful

### Issue 5: sft.py CLI Arguments Mismatch
**Severity:** Medium (UX issue)
**Status:** Needs investigation

**Observation:**
- Launcher scripts use `--mode server` and `--mode client`
- Need to verify sft.py argument parser supports these flags

**Fix:**
```bash
# Verify current arguments
grep -A 20 "argparse.ArgumentParser" sft.py
```

If mismatch found, update launcher scripts or sft.py parser.

---

## PART 5: RECOMMENDATIONS & NEXT STEPS

### Immediate Actions (Next 48 Hours)

1. **Create Launcher Scripts Template**
   - Generate sft.bat, sft-server.bat, sft-client.bat
   - Place in `windows/installer/launchers/`
   - Update .gitignore to exclude (will be regenerated at build)

2. **Create Placeholder Icon**
   - Use generic lock icon or extract from Python
   - Replace `PLACEHOLDER` text file with actual .ico
   - Document in README to replace with custom icon

3. **Test Build Process**
   - Run `build-installer.ps1` on Windows VM
   - Document all errors encountered
   - Fix critical blocking issues

4. **Verify sft.py Arguments**
   - Check if `--mode server/client` exists or needs implementation
   - Update launchers or sft.py accordingly

### Short-Term (Next 2 Weeks)

1. **Implement Security Enhancements**
   - Add Python embedded checksum verification
   - Add pip hash verification
   - Generate post-build checksums

2. **Complete Testing Suite**
   - Test on Windows 8.1, 10, 11
   - Test silent installation
   - Test uninstallation cleanup
   - Test upgrade scenario

3. **Documentation**
   - Update README.md with complete Windows installation guide
   - Create TESTING.md for QA team
   - Add troubleshooting section for common issues

4. **Prepare for Release**
   - Draft GitHub release notes
   - Create checksum generation script
   - Set up code signing (if cert available)

### Long-Term (Next Month)

1. **Code Signing**
   - Obtain certificate
   - Implement signing in build process
   - Test signed installer on various Windows versions

2. **Automated Testing**
   - Create GitHub Actions workflow for builds
   - Set up Windows VM for automated testing
   - Implement smoke test suite

3. **Alternative Distribution**
   - Explore Chocolatey packaging
   - Consider winget manifest
   - Evaluate MSI wrapper for enterprise

4. **Monitoring & Feedback**
   - Track download statistics
   - Monitor issue reports
   - Collect user feedback on installation experience

---

## PART 6: TECHNICAL REFERENCE

### Build Script Analysis

**PowerShell Script Structure:**
- 9 discrete steps (prerequisites → final installer)
- Skip flags for incremental builds (SkipRustBuild, SkipDependencies, etc.)
- Error handling with `$ErrorActionPreference = "Stop"`
- Colored output for user feedback

**Critical Paths:**
1. `target/wheels/*.whl` → Extract .pyd → Inno Setup
2. `installer/python-embedded/` → Modify _pth → Bundle
3. `installer/site-packages/` → Cleanup → Bundle

### Inno Setup Script Analysis

**Key Features:**
- LZMA2 ultra64 compression (line 42)
- Component-based installation (core, python, rustmodule, shortcuts)
- VC++ Redistributable detection via registry (VCRedistNeedsInstall)
- Post-install python311._pth modification (CurStepChanged)
- Comprehensive uninstaller (UninstallDelete section)

**Security Considerations:**
- Admin privileges required (PrivilegesRequired=admin)
- Code signing hooks present but commented (lines 45-46)
- No executable code embedded (all in [Code] section, auditable)

### Dependency Analysis

**Python Dependencies (from requirements.txt):**
```
cryptography==46.0.3    # OpenSSL bindings (CRITICAL)
PyNaCl==1.5.0           # libsodium bindings (CRITICAL)
PySocks==1.7.1          # SOCKS proxy support
jsonschema==4.25.1      # Message validation
pytest==8.4.2           # Testing only (exclude from installer)
maturin==1.7.0          # Build-time only (exclude)
```

**Action:** Create `requirements-runtime.txt` excluding build/test deps:
```
cryptography==46.0.3 --hash=sha256:...
PyNaCl==1.5.0 --hash=sha256:...
PySocks==1.7.1 --hash=sha256:...
jsonschema==4.25.1 --hash=sha256:...
attrs==25.4.0 --hash=sha256:...
```

Update build script line 154 to use `requirements-runtime.txt`.

### Rust Module Details

**Cargo.toml Configuration:**
- Static linking enabled (target.x86_64-pc-windows-msvc)
- Release optimizations: LTO=true, opt-level=3, strip=true
- Security: zeroize feature for memory clearing

**Dependencies:**
- pyo3: Python bindings
- aes-gcm: Authenticated encryption
- ed25519-dalek: Digital signatures
- x25519-dalek: Key exchange
- subtle: Constant-time operations

**Build Output:**
- Size: ~2-4 MB (stripped)
- ABI: cp311 (Python 3.11)
- Platform: win_amd64

---

## CONCLUSION

### Project Status: 90% Complete

**What Works:**
- Complete build infrastructure (PowerShell + Bash scripts)
- Comprehensive Inno Setup configuration
- Automated dependency bundling
- Cross-platform build support

**What's Missing:**
- Launcher scripts (generated at build time - intentional)
- Application icon (placeholder exists)
- Security enhancements (checksums, signing)
- Testing and validation

### Primary Recommendation: DO NOT REDESIGN

The architecture is sound and follows industry best practices. Focus efforts on:
1. Completing missing components (icon, checksums)
2. Testing the build process thoroughly
3. Implementing security enhancements
4. Documenting the complete workflow

### Estimated Time to First Release

- **With current resources:** 3-5 days
  - Day 1: Create icon, test build process, fix blockers
  - Day 2: Implement checksum verification, test on VMs
  - Day 3: Complete functional testing, generate checksums
  - Day 4: Create documentation, prepare GitHub release
  - Day 5: Final validation, publish release

- **With code signing:** Add 1-2 days for certificate acquisition

### Success Criteria

A successful Windows installer release will:
- ✓ Install on Windows 8-11 without errors
- ✓ Bundle all dependencies (no internet required post-install)
- ✓ Create working Start Menu shortcuts
- ✓ Load Rust crypto module successfully
- ✓ Complete file transfer operations
- ✓ Uninstall cleanly without residue
- ✓ Include verified checksums for download integrity
- ✓ (Optional) Code signed to eliminate SmartScreen warnings

---

**Document Author:** Sentinel (SFT Security Lead)
**Review Status:** Ready for Implementation
**Next Action:** Create launcher scripts and test icon, then run first build
