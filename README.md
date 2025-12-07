# Secure File Transfer (SFT)

[![Python Version](https://img.shields.io/badge/python-3.9%2B-blue)](https://www.python.org/)
[![Version](https://img.shields.io/badge/version-2.0.1-blue)](https://github.com/Yul-1/SFT)
[![Security](https://img.shields.io/badge/security-hardened-blueviolet)](https://github.com/Yul-1/SFT)
[![License](https://img.shields.io/badge/license-MIT-green)](https://github.com/Yul-1/SFT)

## Overview

Secure File Transfer (SFT) is a hardened bidirectional file transfer system designed with a "security-first" architecture. The project demonstrates production-grade implementation of cryptographic protocols, memory-safe low-level programming, and defense-in-depth security principles.

**Current version: 2.0.1** - Security enhancements and cryptographic hardening based on penetration testing results.

## Project Structure

This repository contains three independent implementations of the SFT protocol, each optimized for different platforms and deployment scenarios:

```
SFT/
├── README.md                    # This file
├── .gitignore                   # Unified ignore rules (Python/C/Rust/Windows)
│
├── C/                           # C implementation (Linux/Unix)
│   ├── README.md                # C-specific documentation
│   ├── sft.py                   # Protocol layer (Python)
│   ├── python_wrapper.py        # Cryptographic wrapper
│   ├── crypto_accelerator.c     # C acceleration module (OpenSSL)
│   ├── requirements.txt         # Python dependencies
│   ├── system_requirements.txt  # System dependencies (GCC, OpenSSL)
│   └── tests/                   # Comprehensive test suite
│
├── RUST/                        # Rust implementation (Linux/Unix)
│   ├── README.md                # Rust-specific documentation
│   ├── sft.py                   # Protocol layer (Python)
│   ├── python_wrapper.py        # Cryptographic wrapper
│   ├── Cargo.toml               # Rust project configuration (v2.0.1)
│   ├── src/lib.rs               # Rust cryptographic module
│   ├── requirements.txt         # Python dependencies (includes maturin)
│   ├── system_requirements.txt  # System dependencies (Rust toolchain)
│   └── tests/                   # Comprehensive test suite
│
└── Windows/                     # Windows installer (standalone)
    ├── README.md                # Windows installer documentation
    ├── LICENSE                  # MIT License
    └── installer/               # Inno Setup build infrastructure
        ├── sft-setup.iss        # Installer script (v2.0.1)
        ├── build-installer.ps1  # Windows build script
        ├── build-installer-linux.sh  # Cross-platform build script
        ├── assets/              # Icons and resources
        ├── docs/                # Installation guides
        └── launchers/           # Windows batch launchers
```

## Implementation Comparison

| Feature | C Implementation | Rust Implementation | Windows Installer |
|---------|-----------------|---------------------|-------------------|
| **Platform** | Linux/Unix (primary) | Linux/Unix | Windows 8+ |
| **Cryptography** | OpenSSL (C extension) | Pure Rust (ring, dalek) | Uses Rust crypto module |
| **Performance** | 9-12x faster than Python | 8-11x faster than Python | Same as Rust |
| **Memory Safety** | Manual (requires audits) | Compiler-enforced | Rust guarantees |
| **Dependencies** | System OpenSSL 1.1.1+ | Self-contained | Bundled embedded Python |
| **Best For** | Linux servers | Cross-platform Unix | Windows deployment |

### Technical Differences

#### C Implementation
- **Strengths**: Mature OpenSSL library, slightly better raw performance on Linux
- **Challenges**: Manual memory management, platform-specific builds, OpenSSL version dependencies
- **Use Case**: High-performance Linux servers where OpenSSL is already present

#### Rust Implementation
- **Strengths**: Memory safety guarantees, no runtime dependencies, modern toolchain
- **Challenges**: Larger binary size, newer toolchain required
- **Use Case**: Security-critical applications, cross-platform Unix deployments

#### Windows Installer
- **Strengths**: Standalone .exe, bundled Python runtime, no manual installation
- **Challenges**: Larger download size (~50-70 MB), Windows-only
- **Use Case**: Windows desktops/servers, end-user distribution

**Cryptographic Compatibility**: All implementations use identical protocols and are fully interoperable. Clients and servers can mix implementations freely.

## Quick Start

### Using C Implementation (Linux/Unix)

```bash
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
```

### Using Rust Implementation (Linux/Unix)

```bash
cd RUST/

# Install Rust toolchain (if not already installed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"

# Setup virtual environment
python3 -m venv venv
source venv/bin/activate

# Install Python dependencies and compile Rust module
pip install -r requirements.txt
python3 python_wrapper.py --compile

# Start server
python3 sft.py --mode server --port 5555

# Transfer file (from another terminal)
python3 sft.py --mode client --connect localhost:5555 --file document.pdf
```

### Using Windows Installer

```powershell
# Build installer (see Windows/README.md for details)
cd Windows\installer
.\build-installer.ps1

# Or download pre-built installer
# Run SFT-Setup-2.0.1-win64.exe
# Launch from Start Menu
```

## Core Features

### Security Architecture
- **AES-256-GCM**: Authenticated encryption with integrity verification
- **ECDH (X25519)**: Elliptic curve key exchange for session keys
- **Ed25519**: Digital signatures for authentication and non-repudiation
- **HMAC-SHA256**: Message authentication codes
- **PBKDF2**: Key derivation with 100,000 iterations
- **AAD Protection**: Authenticated packet headers prevent tampering

### Advanced Protections
- **Anti-DoS**: Intelligent rate limiting, connection pooling, ECDH prevents RSA exhaustion
- **Anti-Replay**: Timestamp validation, message ID tracking, sliding window algorithm (10000 entries)
- **Anti-Timing**: Constant-time comparisons prevent side-channel attacks
- **Path Traversal Protection**: Strict filename sanitization and validation
- **Memory Safety**: Secure key scrubbing after use (explicit_bzero/zeroize)
- **Zombie File Protection**: Automatic cleanup of corrupted downloads

### Protocol Features
- **Bidirectional Transfer**: Upload files to server, download from server
- **Remote Listing**: Query available files before download
- **Resume Support**: Automatic resumption of interrupted transfers
- **Proxy Support**: SOCKS4/SOCKS5/HTTP proxy connectivity
- **Thread-Safe**: Complete session isolation for concurrent connections
- **Comprehensive Logging**: Detailed audit trail with automatic rotation

## Detailed Documentation

Each implementation directory contains comprehensive documentation:

- **C/README.md**: C implementation guide, OpenSSL integration, Linux optimization
- **RUST/README.md**: Rust implementation guide, memory safety, cross-platform builds
- **Windows/README.md**: Windows installer build guide, Inno Setup configuration, deployment

## Security Model

SFT implements defense-in-depth with multi-layer protections:

| Layer | Protections |
|-------|------------|
| **Network** | Rate limiting, connection pooling, socket timeouts |
| **Protocol** | Message authentication (HMAC), replay detection, schema validation |
| **Cryptographic** | ECDH key exchange, Ed25519 signatures, AES-GCM encryption with AAD |
| **Memory** | Secure key scrubbing, buffer limits, stack protection |

### Threat Mitigation Matrix

| Threat | Mitigation |
|--------|-----------|
| DoS/DDoS | Rate limiting, connection limits, ECDH (no RSA exhaustion) |
| Replay Attack | Message ID FIFO queue, timestamp validation (5-min window) |
| Replay Bypass | Sliding window algorithm (10000 entries) prevents queue flooding |
| Timing Attack | Constant-time comparisons (CRYPTO_memcmp/subtle::ConstantTimeEq) |
| MITM | ECDH key exchange + Ed25519 authentication |
| Packet Tampering | AAD authentication on all packet headers |
| Path Traversal | Filename sanitization, basename extraction, strict validation |
| Memory Leaks | Explicit scrubbing (C: explicit_bzero, Rust: zeroize) |

## Testing

All implementations include comprehensive test suites (50+ test cases):

```bash
# Run all tests
python3 -m pytest tests/ -v

# Specific test categories
python3 -m pytest tests/test_crypto_accelerator.py -v    # Cryptographic operations
python3 -m pytest tests/test_security_protocol.py -v     # Protocol security
python3 -m pytest tests/test_dos_mitigation.py -v        # DoS protections
python3 -m pytest tests/test_concurrency.py -v           # Thread safety
```

## Performance Benchmarks

Comparative performance (10MB AES-256-GCM encryption):

| Implementation | Encryption Time | vs Pure Python |
|----------------|----------------|----------------|
| Pure Python | 385ms | 1.0x (baseline) |
| C Module | 42ms | 9.2x faster |
| Rust Module | 45ms | 8.6x faster |

Full benchmarks and profiling data are available in each implementation's README.

## Version History

**2.0.1** (Current):
- Security remediations based on comprehensive penetration testing
- Enhanced symlink attack protection with O_NOFOLLOW
- Strengthened X25519 public key validation against weak points
- Improved filename sanitization with URL decoding and Unicode normalization
- Enhanced memory clearing using ctypes.memset for guaranteed zeroing
- Increased PBKDF2 iterations from 100,000 to 600,000 (OWASP 2024 recommendation)
- Strengthened sequence number validation to prevent replay attacks
- Updated cryptography library to version 43.0.1
- Comprehensive security hardening across all implementations

**2.0.0**:
- Repository reorganization: Separated C, Rust, and Windows implementations
- Independent versioning for each implementation
- Streamlined build processes
- Enhanced documentation per implementation

**1.8.0**:
- Proxy support (SOCKS4/SOCKS5/HTTP)
- Critical fix: Source file truncation prevention
- Comprehensive proxy testing guide

**1.7.0**:
- Migration from RSA to ECDH (X25519)
- Ed25519 digital signatures
- Zombie file protection
- Replay bypass mitigation

See individual implementation READMEs for complete version history.

## Choosing an Implementation

**Choose C implementation if:**
- Deploying on Linux servers with OpenSSL already installed
- Seeking maximum performance on established infrastructure
- Comfortable with manual memory management audits

**Choose Rust implementation if:**
- Require memory safety guarantees at compile time
- Need self-contained binaries with minimal runtime dependencies
- Prefer modern toolchain with built-in package management

**Choose Windows installer if:**
- Deploying on Windows 8+ systems
- Need standalone executable for end-users
- Want bundled Python runtime with zero manual setup

**All implementations:**
- Use identical protocols (fully interoperable)
- Provide automatic fallback to pure Python if compilation fails
- Include comprehensive test suites
- Support all SFT protocol features

## Contributing

Contributions are welcome. Please ensure:
- Python code follows PEP 8 (line length 100)
- C code follows Linux kernel style
- Rust code follows Rustfmt conventions
- All tests pass (minimum 80% coverage for new features)
- Commit messages use conventional format: `type(scope): description`

## License

MIT License - See implementation directories for full license text.

## Contact

- **GitHub**: [@Yul-1](https://github.com/Yul-1)
- **Issues**: [GitHub Issues](https://github.com/Yul-1/SFT/issues)
- **Email**: yul.cysec@gmail.com
