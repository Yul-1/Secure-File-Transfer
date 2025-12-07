# Secure File Transfer (SFT)

[![Python Version](https://img.shields.io/badge/python-3.9%2B-blue)](https://www.python.org/)
[![Version](https://img.shields.io/badge/version-1.8.0-blue)](https://github.com/Yul-1/SFT)
[![Security](https://img.shields.io/badge/security-hardened-blueviolet)](https://github.com/Yul-1/SFT)
[![License](https://img.shields.io/badge/license-MIT-green)](https://github.com/Yul-1/SFT)

## Overview

Secure File Transfer (SFT) is a hardened bidirectional file transfer system designed with a "security-first" architecture. The project demonstrates production-grade implementation of cryptographic protocols, memory-safe low-level programming, and defense-in-depth security principles.

**Current version: 1.8.0** - Full support for secure upload, download, remote file listing, and proxy connectivity with ECDH key exchange and Ed25519 authentication.

## Project Structure

This repository contains two complete implementations of the SFT protocol, each optimized for different deployment scenarios:

```
SFT/
├── README.md                                    # This file
├── .gitignore                                   # Unified ignore rules (Python/C/Rust)
│
├── Linux_and_other_distribution_(C)/            # Original C implementation
│   ├── README.md                                # C-specific documentation
│   ├── sft.py                                   # Protocol layer (Python)
│   ├── python_wrapper.py                        # Cryptographic wrapper
│   ├── crypto_accelerator.c                     # C acceleration module (OpenSSL)
│   ├── requirements.txt                         # Python dependencies
│   ├── system_requirements.txt                  # System dependencies (GCC, OpenSSL)
│   └── tests/                                   # Comprehensive test suite
│
└── Linux_and_other_distribution_(RUST)/         # Rust implementation (Windows-compatible)
    ├── README.md                                # Rust-specific documentation
    ├── sft.py                                   # Protocol layer (Python)
    ├── python_wrapper.py                        # Cryptographic wrapper
    ├── Cargo.toml                               # Rust project configuration
    ├── src/lib.rs                               # Rust cryptographic module
    ├── requirements.txt                         # Python dependencies (includes maturin)
    ├── system_requirements.txt                  # System dependencies (Rust toolchain)
    └── tests/                                   # Comprehensive test suite
```

## Implementation Comparison

| Feature | C Implementation | Rust Implementation |
|---------|-----------------|---------------------|
| **Cryptography Backend** | OpenSSL (via C extension) | Pure Rust (ring, aes-gcm, ed25519-dalek) |
| **Performance** | 9-12x faster than pure Python | 8-11x faster than pure Python |
| **Memory Safety** | Manual (requires audits) | Compiler-enforced (borrow checker) |
| **Platform Support** | Linux (primary), macOS, Windows (requires MSVC) | Linux, macOS, Windows (no MSVC required) |
| **Compilation** | GCC/Clang + OpenSSL headers | Rust toolchain (rustc + cargo) |
| **Dependencies** | System OpenSSL 1.1.1+ | Self-contained (statically linked) |
| **Best For** | Production Linux servers | Cross-platform deployment, Windows |

### Technical Differences

#### C Implementation
- **Strengths**: Mature OpenSSL library, slightly better raw performance on Linux
- **Challenges**: Manual memory management, platform-specific builds, OpenSSL version dependencies
- **Use Case**: High-performance Linux servers where OpenSSL is already present

#### Rust Implementation
- **Strengths**: Memory safety guarantees, no runtime dependencies, simplified Windows builds
- **Challenges**: Larger binary size, newer toolchain required
- **Use Case**: Cross-platform deployments, Windows environments, security-critical applications requiring memory safety

**Cryptographic Compatibility**: Both implementations use identical protocols and are fully interoperable. A client using the C module can communicate seamlessly with a server using the Rust module and vice versa.

## Quick Start

### Using C Implementation (Linux/macOS)

```bash
cd "Linux_and_other_distribution_(C)"

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

### Using Rust Implementation (Windows/Linux/macOS)

```bash
cd "Linux_and_other_distribution_(RUST)"

# Install Rust toolchain (if not already installed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"

# Setup virtual environment
python3 -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install Python dependencies and compile Rust module
pip install -r requirements.txt
python3 python_wrapper.py --compile

# Start server
python3 sft.py --mode server --port 5555

# Transfer file (from another terminal)
python3 sft.py --mode client --connect localhost:5555 --file document.pdf
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

- **README.md**: Complete installation guide, usage examples, architecture details, performance benchmarks
- **system_requirements.txt**: Platform-specific system dependencies
- **requirements.txt**: Python package dependencies

## Security Model

SFT implements defense-in-depth with multi-layer protections:

| Layer | Protections |
|-------|------------|
| **Network** | Rate limiting, connection pooling, socket timeouts |
| **Protocol** | Message authentication (HMAC), replay detection, schema validation |
| **Cryptographic** | ECDH key exchange, Ed25519 signatures, AES-GCM encryption with AAD |
| **Memory** | Secure key scrubbing, buffer limits, stack protection (where applicable) |

### Threat Mitigation Matrix

| Threat | Mitigation |
|--------|-----------|
| DoS/DDoS | Rate limiting, connection limits, ECDH (no RSA exhaustion) |
| Replay Attack | Message ID FIFO queue (1000 entries), timestamp validation (5-min window) |
| Replay Bypass | Sliding window algorithm (10000 entries) prevents queue flooding |
| Timing Attack | Constant-time comparisons (CRYPTO_memcmp/subtle::ConstantTimeEq) |
| MITM | ECDH key exchange + Ed25519 authentication |
| Packet Tampering | AAD authentication on all packet headers |
| Path Traversal | Filename sanitization, basename extraction, strict validation |
| Memory Leaks | Explicit scrubbing (C: explicit_bzero, Rust: zeroize) |

## Testing

Both implementations include comprehensive test suites (50+ test cases):

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

**1.8.0** (Current):
- Proxy support (SOCKS4/SOCKS5/HTTP)
- Critical fix: Source file truncation prevention
- Comprehensive proxy testing guide

**1.7.0**:
- Migration from RSA to ECDH (X25519)
- Ed25519 digital signatures
- Zombie file protection
- Replay bypass mitigation

See individual READMEs for complete version history.

## Choosing an Implementation

**Choose C implementation if:**
- Deploying on Linux servers with OpenSSL already installed
- Seeking maximum performance on established infrastructure
- Comfortable with manual memory management audits

**Choose Rust implementation if:**
- Deploying on Windows without Visual Studio
- Require memory safety guarantees at compile time
- Need self-contained binaries with minimal runtime dependencies
- Prefer modern toolchain with built-in package management

**Both implementations:**
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
