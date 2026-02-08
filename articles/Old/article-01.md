# When "Sending a File" Isn't That Simple

**The problem space - why secure file transfer is more complex than it seems**

---

## The 2:47 AM Alert

The SOC monitor's screen flickered at 2:47 AM. Alert severity: HIGH. An intercepted file transfer. Plaintext FTP. The packet capture revealed everything: medical records, authentication tokens, internal API keys. The attacker hadn't even needed sophisticated tools. A passive network tap at a coffee shop, Wireshark running in promiscuous mode, and patience.

The incident response began immediately. Credentials rotated. Affected patients notified. Regulatory paperwork initiated. The estimated cost: $340,000 in direct remediation, untold reputational damage, and a mandatory external security audit.

During the post-mortem, the team asked the obvious question: "Why weren't we using encrypted transfer?" The answer was equally obvious and frustrating: "We were using HTTPS for web uploads, but the automated batch system still ran on legacy FTP because migrating seemed too complex."

The decision came swift and decisive: "Let's build it ourselves. A secure file transfer system that handles everything: authentication, encryption, integrity verification, and performance. No excuses, no legacy compromises."

This series documents that journey. From threat modeling to production deployment with native C and Rust accelerators. What started as a security incident became a deep education in applied cryptography, protocol design, and systems engineering.

## The Problem Surface

Sending a file from point A to point B sounds trivial. Open a socket, stream bytes, close the connection. Developers have been doing this since the 1980s. So why is "secure" file transfer so much harder?

Because networks are hostile environments, and every byte you transmit is an opportunity for an attacker. The threat surface expands in multiple dimensions simultaneously.

**Man-in-the-Middle (MITM)**: Between your client and server sit routers, switches, ISPs, VPNs, proxies, and countless other network devices. Any of them can be compromised. An attacker positioned on the network path can intercept, read, and modify your traffic in real-time. Without cryptographic protection, they see plaintext. With naive encryption, they can still tamper with ciphertext and cause controlled corruption.

**Replay Attacks**: Capture a legitimate encrypted packet at 3:00 PM. Replay it at 3:15 PM. If the system doesn't track message uniqueness, the server accepts the duplicate. Financial transactions get processed twice. Authentication tokens grant repeated access. The attack requires no cryptographic breaks, just network recording and retransmission.

**Packet Tampering**: Flip a single bit in transit. If integrity protection is absent or weak, corrupted data passes validation. In the best case, you get garbage output. In the worst case, carefully crafted bit flips exploit parser vulnerabilities or business logic flaws. The attacker doesn't need to decrypt; they just need to predictably damage.

**Authentication Failure**: Who are you talking to? Without strong mutual authentication, the client can't verify the server is legitimate, and the server can't verify the client's identity. Attackers run fake servers that mimic the real one, harvesting credentials and data from unsuspecting clients. Or they impersonate clients to exfiltrate data from trusting servers.

**Denial of Service (DoS)**: Flood the server with handshake requests. Force expensive cryptographic operations. Exhaust CPU, memory, or network bandwidth. The server becomes unresponsive to legitimate users. Traditional RSA-based key exchange is particularly vulnerable: signature verification is computationally expensive, and attackers can send thousands of fake handshake attempts per second with minimal effort.

Real-world examples are not hypothetical. Run `nmap -p 21 [target]` and watch FTP servers advertise themselves. Capture FTP traffic with Wireshark: `tcpdump -i eth0 port 21 -A`. The username, password, and file contents are right there in ASCII. No decryption needed. Just passive observation.

The stakes get higher with every file transferred. Medical records. Financial data. Proprietary source code. Authentication credentials. The question isn't "if" an attack will be attempted, but "when" and "how sophisticated."

## CIA in the Real World

Security textbooks love the CIA triad: Confidentiality, Integrity, Availability. Abstract principles that sound good in presentations but feel distant from actual code. The Secure File Transfer (SFT) project forced us to map each principle to concrete technical decisions with measurable trade-offs.

**Confidentiality: AES-256-GCM, Not CBC, Not CTR Alone**

Confidentiality means adversaries can't read the data. The obvious solution: encrypt it. But "encrypt" is not a single operation; it's a family of algorithms, modes, and configurations, each with different security properties.

We chose AES-256-GCM (Galois/Counter Mode). AES-256 provides the encryption: a symmetric block cipher with 256-bit keys, considered unbreakable by brute force with current or foreseeable technology. GCM provides authenticated encryption: it produces both ciphertext and an authentication tag. The tag proves that the ciphertext hasn't been tampered with.

Why not AES-CBC (Cipher Block Chaining)? CBC requires separate authentication via HMAC. Implementing encrypt-then-MAC correctly is error-prone; getting the order wrong or using separate keys opens the door to padding oracle attacks and other cryptographic failures. GCM gives us authentication built-in, eliminating an entire class of implementation mistakes.

Why not AES-CTR (Counter Mode) alone? CTR turns AES into a stream cipher, fast and parallelizable. But it provides zero integrity protection. An attacker can flip bits in the ciphertext and cause predictable changes in the plaintext without detection. CTR requires external MAC. GCM combines both: encryption and authentication in one operation.

The nonce (number used once) is critical. GCM requires a unique nonce for every encryption operation with the same key. Reuse the nonce, and you break confidentiality catastrophically. SFT generates 12-byte nonces using `secrets.token_bytes(12)` from Python's cryptographically secure random number generator, seeded from the OS entropy pool.

**Integrity: HMAC vs Authentication Tags**

Integrity means detecting tampering. If an attacker modifies even a single bit in transit, the receiver must know.

AES-GCM's authentication tag already provides message-level integrity. Every encrypted chunk includes a 16-byte tag computed over both the ciphertext and optional Additional Authenticated Data (AAD). Verification happens during decryption: if the tag doesn't match, decryption fails with an authentication error. No separate HMAC needed.

But we go further. Packet headers contain metadata: version, payload type, length, sequence number. These headers aren't secret, so encrypting them serves no purpose. But they must not be tampered with. An attacker could modify the sequence number to cause replay or reordering. Solution: pass the binary-packed header as AAD to AES-GCM. The authentication tag covers both the encrypted payload and the plaintext header. Tampering with either causes tag verification to fail.

This is defense-in-depth. Even if an implementation bug weakened one protection layer, the other would catch the attack.

**Availability: Rate Limiting, Connection Pooling, ECDH**

Availability means the system remains responsive to legitimate users even under attack. DoS attacks exploit expensive operations to exhaust server resources.

Traditional TLS-style handshakes used RSA. The client sends an RSA-encrypted session key; the server decrypts it with its private key. RSA decryption is slow: a 4096-bit private key operation takes ~3ms on modern hardware. An attacker can send 300 fake handshakes per second from a single core, forcing the server to burn 90% CPU on bogus cryptography.

SFT uses Elliptic Curve Diffie-Hellman (ECDH) with X25519. Both client and server generate ephemeral key pairs and exchange public keys. The shared secret is computed via scalar multiplication, which is fast: sub-millisecond on typical hardware. ECDH also provides Perfect Forward Secrecy: even if long-term keys are compromised, past session keys remain secure because they were derived from ephemeral keys that no longer exist.

Beyond cryptography, we implement layered DoS defenses:

- **Rate limiting**: Maximum 100 requests per 60-second window per IP address. Tracked in-memory with a sliding window. Violators get connection refused.
- **Connection pooling**: Maximum 50 concurrent connections globally. Prevents memory exhaustion from thousands of open but idle sockets.
- **Idle timeout**: Connections with no activity for 60 seconds are terminated. Prevents slowloris-style attacks where attackers hold connections open indefinitely.
- **Sequence number validation**: Strict monotonic increase. Out-of-order packets are rejected. Prevents attackers from flooding the receiver with old packets to exhaust replay detection memory.

| CIA Principle | SFT Implementation | Alternative Considered | Why Rejected |
|---------------|-------------------|----------------------|-------------|
| **Confidentiality** | AES-256-GCM | AES-256-CBC + HMAC | Requires separate MAC, error-prone to implement correctly |
| | | ChaCha20-Poly1305 | Excellent choice, but less hardware acceleration on x86 servers |
| **Integrity** | GCM authentication tag + AAD on headers | Separate HMAC-SHA256 | Redundant with GCM tag, adds complexity |
| | | CRC32 or Adler32 | Not cryptographically secure, easily forged |
| **Availability** | ECDH (X25519) key exchange | RSA key exchange | 21x slower, enables CPU exhaustion DoS |
| | Rate limiting (100/min/IP) | No rate limiting | Allows handshake flood attacks |
| | Connection pooling (max 50) | Unlimited connections | Memory exhaustion vulnerability |

## Threat Modeling: STRIDE Applied

STRIDE (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege) is Microsoft's threat modeling framework. It forces systematic thinking about what can go wrong. Applied to file transfer:

| Threat | Example Scenario | SFT Response |
|--------|-----------------|-------------|
| **Spoofing** | Attacker runs fake server at `evil.com`, client connects thinking it's legitimate | Ed25519 digital signatures on handshake messages. Server signs its public key with long-term identity key. Client verifies signature against known public key. MITM cannot forge signatures without stealing the private key. |
| **Tampering** | Attacker intercepts packet, flips bit in header to change sequence number from 42 to 43, causing packet reordering | Binary-packed header passed as AAD to AES-GCM. Authentication tag covers header. Any modification causes tag verification failure and packet rejection. |
| **Repudiation** | User claims "I didn't send that file," denying responsibility for the transfer | Ed25519 signatures on critical messages provide non-repudiation. Signed handshake proves identity. Logs capture signatures and can be verified later as evidence. |
| **Information Disclosure** | Passive eavesdropper captures encrypted traffic, attempts to extract plaintext | AES-256-GCM encryption with unique nonces. Even identical files produce different ciphertext on each transfer. Passive attacks yield only encrypted bytes. Active attacks are detected via authentication tags. |
| **Denial of Service** | Attacker floods server with 10,000 handshake requests per second, exhausting CPU | Rate limiting (100 req/min/IP). ECDH instead of RSA (faster). Connection pooling (max 50 concurrent). Idle timeout (60s). Multi-layer defense makes resource exhaustion economically infeasible. |
| **Elevation of Privilege** | Attacker sends filename `../../etc/passwd`, attempts to read arbitrary files from server | Filename sanitization: `os.path.basename()` strips path separators. Only base filename is used. Directory traversal is impossible. Files are saved to a designated `ricevuti/` directory with no path expansion. |

Beyond STRIDE, we identified attacker profiles and their capabilities:

**Passive Eavesdropper**: Monitors network traffic but doesn't modify it. Capabilities: record all packets, perform statistical analysis, attempt cryptanalysis on captured ciphertext. Threat level: MEDIUM. Mitigated by strong encryption (AES-256-GCM) and unique nonces preventing plaintext correlation.

**Active Man-in-the-Middle**: Intercepts and modifies traffic in real-time. Capabilities: read, modify, inject, drop packets. Can also replay old packets. Threat level: HIGH. Mitigated by authentication tags (tampering detection), sequence numbers (replay prevention), and mutual authentication (identity verification).

**Resource Exhaustion Attacker**: Sends high volumes of malicious traffic to degrade service. Capabilities: open thousands of connections, send malformed packets, trigger expensive operations. Threat level: HIGH. Mitigated by rate limiting, connection pooling, fast ECDH handshake, input validation, and fail-fast error handling.

## The SFT Architecture

To handle these threats without collapsing under complexity, SFT is structured in three distinct layers. Each layer has a single responsibility, clear interfaces, and can be tested independently.

```
+---------------------------------------------------------------+
|                      PROTOCOL LAYER                           |
|                        (sft.py)                               |
|                                                               |
|  - TCP socket management                                      |
|  - Handshake protocol: HELLO -> CHALLENGE -> RESPONSE        |
|  - Session state machine: disconnected -> handshaking ->     |
|    authenticated -> transferring -> closed                    |
|  - Chunking, sequencing, replay protection                    |
|  - Wire format: binary headers + encrypted payloads          |
|  - Error handling, retries, connection recovery              |
+---------------------------------------------------------------+
                             |
                             | Calls crypto operations via
                             v
+---------------------------------------------------------------+
|                    WRAPPER LAYER                              |
|                  (python_wrapper.py)                          |
|                                                               |
|  - Unified cryptographic API                                  |
|  - Automatic fallback: Try C module -> Try Rust module ->    |
|    Fall back to pure Python                                   |
|  - Input validation, buffer size limits (DoS prevention)      |
|  - Thread-safe key caching (LRU, max 3 keys)                 |
|  - Statistics tracking: native calls vs fallback calls       |
|  - Secure memory clearing (best-effort in Python)            |
+---------------------------------------------------------------+
                             |
                             | FFI calls
                             v
+---------------------------------------------------------------+
|                      CORE LAYER                               |
|          (crypto_accelerator.c / crypto_accelerator.so)       |
|          (RUST/src/lib.rs -> crypto_accelerator.cpython)      |
|                                                               |
|  C Module (OpenSSL):                                          |
|  - EVP API for AES-256-GCM                                   |
|  - RAND_bytes() for CSPRNG                                   |
|  - CRYPTO_memcmp() for constant-time comparison              |
|  - explicit_bzero() for secure memory zeroing                |
|                                                               |
|  Rust Module (pure Rust crates):                             |
|  - aes-gcm crate for AES-256-GCM                             |
|  - x25519-dalek for ECDH                                     |
|  - ed25519-dalek for digital signatures                      |
|  - zeroize crate for memory clearing                         |
|  - subtle crate for constant-time operations                 |
+---------------------------------------------------------------+
```

**Why Three Layers?**

Separation of concerns. The protocol layer knows nothing about OpenSSL or Rust. It just calls `encrypt_aes_gcm()` and receives ciphertext. The wrapper layer knows nothing about TCP sockets or sequence numbers. It validates inputs and delegates to the fastest available implementation. The core layer knows nothing about handshakes or file chunking. It performs low-level cryptographic operations at maximum speed.

This structure enables independent testing. We can unit test the C module with known test vectors from NIST. We can test the wrapper's fallback logic by simulating C module load failure. We can test the protocol layer with mocked crypto functions. Each layer has a focused responsibility and clear success criteria.

**Why Python + Native?**

Python provides rapid development, rich standard library, excellent debugging, and clear expressiveness. Perfect for protocol logic, state machines, and I/O handling. Terrible for cryptographic performance. AES-GCM in pure Python (even with the `cryptography` library's Python overhead) achieves ~26 MB/s on our test hardware.

Native code (C or Rust) compiled to machine code with SIMD and AES-NI hardware acceleration achieves 200-250 MB/s for the same operation. That's a 10x speedup. For transferring multi-gigabyte files, the difference is critical.

Python's ecosystem includes well-tested crypto libraries (`cryptography`, built on OpenSSL). We use them as fallback. But for production throughput, native modules are essential.

**Why Two Native Implementations (C and Rust)?**

**C with OpenSSL**: The standard. Every Linux server has OpenSSL installed. Battle-tested, audited by thousands of eyes, hardware-optimized. But C requires manual memory management. Every `malloc` needs a `free`. Every buffer needs bounds checks. Every secret needs explicit zeroing. Miss one, and you have a memory leak or use-after-free.

**Rust with pure crates**: Memory safety enforced by the compiler. Use-after-free is impossible. Double-free is impossible. Buffer overflows are caught at compile time. The `zeroize` crate clears secrets automatically when they go out of scope. The borrow checker prevents data races. The type system makes invalid states unrepresentable.

The trade-off: Rust's binary is larger (~800KB vs ~50KB for C) because it statically links all dependencies. Build times are longer. Learning curve is steeper. But the safety guarantees are unmatched.

We maintain both. C for environments where OpenSSL is already present and mature toolchains exist. Rust for greenfield projects, security-critical applications, and teams prioritizing correctness over familiarity.

The wrapper provides automatic selection and fallback. If both modules are available, it uses Rust by default. If Rust compilation fails, it uses C. If neither is available, it falls back to pure Python. The protocol layer doesn't care; it just calls `encrypt_aes_gcm()` and gets correct results.

## Attacker Positions in Network Topology

To make the threat model concrete, visualize where attackers can position themselves:

```
[Client]
   |
   |  (1) Local network tap (coffee shop, compromised router)
   |
[ISP Router]
   |
   |  (2) ISP-level interception (government surveillance, rogue employee)
   |
[Internet Backbone]
   |
   |  (3) BGP hijacking, submarine cable tap
   |
[CDN / Proxy]
   |
   |  (4) Compromised proxy, malicious CDN node
   |
[Server]
```

Position (1): Passive or active MITM at the local network. Easiest for opportunistic attackers. Defended by end-to-end encryption and mutual authentication.

Position (2): ISP-level monitoring. More sophisticated, but still observable from network metadata (IP addresses, timing, packet sizes). Defended by encryption, but metadata leakage remains. Future enhancement: consider traffic padding and timing obfuscation.

Position (3): Nation-state level capabilities. BGP hijacking redirects traffic to attacker-controlled routers. Submarine cable taps provide direct physical access to fiber. Defended by strong mutual authentication (prevents fake endpoints) and Perfect Forward Secrecy (limits damage from long-term key compromise).

Position (4): Compromised intermediaries. If the client trusts a malicious proxy, the proxy can MITM the connection if not end-to-end authenticated. Defended by direct peer authentication (client validates server's Ed25519 signature, bypassing trust in intermediaries).

No system is invulnerable. The goal is to make attacks expensive, detectable, and forensically traceable.

## Series Roadmap

This article set the stage: the problem space, threat model, architectural principles, and security philosophy. The next five articles dive deep into implementation.

**Article 2: The Building Blocks of Modern Cryptography**
From theory to practice: AES-GCM encryption, HMAC authentication, SHA-256 hashing, ECDH key exchange, Ed25519 digital signatures, and PBKDF2 key derivation. Every primitive explained with working Python code you can run and modify.

**Article 3: The Handshake Protocol**
Complete implementation of the four-phase handshake: HELLO, CHALLENGE, RESPONSE, SESSION_ESTABLISHED. Ephemeral key generation, signature verification, shared secret computation, anti-replay tracking, and rate limiting. Line-by-line walkthrough of the code.

**Article 4: The Encryption Pipeline**
File chunking strategy, binary wire format, per-chunk encryption with AAD, sequence number validation, reassembly, integrity verification, resume support, and edge case handling (corrupted chunks, path traversal, zombie files).

**Article 5: Native Accelerators**
FFI with C (OpenSSL) and Rust (pure crypto crates). Complete module implementations. Memory safety patterns. Compilation with security flags. Honest comparison of trade-offs. Benchmark results: 10x speedup.

**Article 6: Benchmarks and Lessons Learned**
End-to-end performance data. Architectural trade-off analysis. Memorable bugs and how they were fixed. Project evolution timeline. Reflections on building cryptographic protocols from scratch as an educational discipline. When to do this, when to use existing solutions.

By the end of this series, you'll understand how modern secure communication works from first principles. You'll have implemented the core components yourself. You'll know where the complexity lives, where the dangers hide, and why "just use TLS" is good advice for production but insufficient for learning.

---

> **Disclaimer**: This series is for educational purposes. The concepts are correct and the code is functional, but production systems should use vetted and audited cryptographic libraries and protocols (TLS, SSH, SFTP). The SFT project underwent penetration testing and multiple security audits during development, but it remains a learning project, not a replacement for industry-standard solutions. Do not use this code in production without thorough review by professional security experts.

---

**Next**: Article 2 - The Building Blocks of Modern Cryptography. Before we can build a secure handshake, we need to understand the cryptographic primitives: AES-GCM, ECDH, Ed25519. From theory to working code.
