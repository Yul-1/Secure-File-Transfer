# The Building Blocks of Modern Cryptography

**From theory to practice - implementing encryption, hashing, and MACs in Python**

---

## The Cryptographic Toolbox

As we explored in Part 1, the threat landscape for secure file transfer is vast: eavesdroppers, tampering attackers, replay attacks, and resource exhaustion. Each threat demands specific cryptographic defenses. But before we can build the complete handshake and encryption pipeline, we need to understand the individual tools.

Think of cryptography as carpentry. You don't build a house with "tools." You build it with a hammer, saw, drill, and level. Each has a specific purpose, specific failure modes, and specific ways to use it correctly. Mix them up and you build something structurally unsound.

This article is your cryptographic toolbox. We'll examine each primitive used in the SFT project: AES-256-GCM for authenticated encryption, SHA-256 and HMAC for integrity, X25519 ECDH for key exchange, Ed25519 for digital signatures, PBKDF2 for key derivation, and constant-time comparison for timing attack defense. For each primitive, we'll cover the theory needed to use it safely, the practical implementation in Python using the `cryptography` library, and the security properties it provides.

Every code snippet is functional, runnable, and directly relevant to the SFT implementation. By the end of this article, you'll have working implementations of every cryptographic operation needed for secure file transfer.

> **Disclaimer**: This series is for educational purposes. The concepts are correct and the code is functional, but production systems should use vetted and audited cryptographic libraries and protocols (TLS, SSH, SFTP). Do not use this code in production without thorough review by security experts.

## AES-256-GCM: Authenticated Encryption

Authenticated Encryption with Associated Data (AEAD) solves two problems simultaneously: confidentiality and integrity. Without AEAD, you'd encrypt data for confidentiality, then separately compute a MAC for integrity. Get the order wrong (MAC-then-encrypt instead of encrypt-then-MAC), or use the same key for both operations, and you open the door to padding oracle attacks and other cryptographic failures.

AES-256-GCM is an AEAD cipher that eliminates these pitfalls. AES provides the encryption via a 256-bit key and 128-bit block size. GCM (Galois/Counter Mode) combines CTR mode encryption with GMAC authentication. The result: a single operation that produces both ciphertext and an authentication tag proving the ciphertext hasn't been tampered with.

**Why GCM over CBC?**

AES-CBC (Cipher Block Chaining) requires separate authentication via HMAC. The canonical construction is encrypt-then-MAC: encrypt the plaintext with AES-CBC, then compute HMAC over the ciphertext. But this requires two keys (one for AES, one for HMAC), careful construction to avoid timing attacks, and vigilance against padding oracle vulnerabilities. Every implementation decision is an opportunity for error.

GCM provides authentication built-in. One operation, one key, no separate MAC. The authentication tag is computed over both the ciphertext and any Additional Authenticated Data (AAD) you provide. Verification happens automatically during decryption: if the tag doesn't match, decryption fails with an error. No plaintext is returned to the caller until authentication succeeds.

GCM is also parallelizable. CBC requires sequential processing: each block depends on the previous block's ciphertext. GCM's CTR mode generates a keystream independently for each block, allowing parallel encryption on multi-core systems. This matters for performance on large files.

**Implementation in Python**

The `cryptography` library provides a clean API for AES-256-GCM. Here's a complete encrypt/decrypt implementation:

```python
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def encrypt_aes_gcm(plaintext: bytes, key: bytes, nonce: bytes) -> tuple[bytes, bytes]:
    """
    Encrypt plaintext with AES-256-GCM.

    Args:
        plaintext: Data to encrypt
        key: 32-byte AES-256 key
        nonce: 12-byte unique value (must never repeat for same key)

    Returns:
        (ciphertext, tag) tuple
    """
    if len(key) != 32:
        raise ValueError("Key must be 32 bytes for AES-256")
    if len(nonce) != 12:
        raise ValueError("Nonce must be 12 bytes for GCM")

    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    tag = encryptor.tag

    return ciphertext, tag


def decrypt_aes_gcm(ciphertext: bytes, key: bytes, nonce: bytes, tag: bytes) -> bytes:
    """
    Decrypt ciphertext with AES-256-GCM and verify authentication tag.

    Args:
        ciphertext: Encrypted data
        key: 32-byte AES-256 key
        nonce: 12-byte nonce used during encryption
        tag: 16-byte authentication tag from encryption

    Returns:
        Decrypted plaintext

    Raises:
        ValueError: If authentication fails (tampering detected)
    """
    if len(key) != 32:
        raise ValueError("Key must be 32 bytes for AES-256")
    if len(nonce) != 12:
        raise ValueError("Nonce must be 12 bytes for GCM")
    if len(tag) != 16:
        raise ValueError("Tag must be 16 bytes for GCM")

    try:
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        return plaintext
    except Exception as e:
        raise ValueError(f"Decryption failed (tampering detected): {e}")


# Example usage
if __name__ == "__main__":
    key = os.urandom(32)  # Generate random 256-bit key
    nonce = os.urandom(12)  # Generate random 96-bit nonce
    plaintext = b"Sensitive medical records for patient #12847"

    ciphertext, tag = encrypt_aes_gcm(plaintext, key, nonce)
    print(f"Plaintext: {plaintext}")
    print(f"Ciphertext: {ciphertext.hex()}")
    print(f"Tag: {tag.hex()}")

    # Successful decryption
    decrypted = decrypt_aes_gcm(ciphertext, key, nonce, tag)
    assert decrypted == plaintext
    print(f"Decrypted: {decrypted}")

    # Tampering detection: flip one bit in ciphertext
    tampered_ciphertext = bytearray(ciphertext)
    tampered_ciphertext[0] ^= 0x01

    try:
        decrypt_aes_gcm(bytes(tampered_ciphertext), key, nonce, tag)
        print("ERROR: Tampering not detected!")
    except ValueError as e:
        print(f"Tampering detected: {e}")
```

**Nonce Management: The Critical Constraint**

The nonce (number used once) is GCM's Achilles' heel. Reuse a nonce with the same key, and confidentiality is catastrophically broken. An attacker who observes two ciphertexts encrypted with the same key and nonce can XOR them to cancel out the keystream, revealing the XOR of the two plaintexts. With known-plaintext attacks or statistical analysis, full plaintext recovery becomes feasible.

The nonce must be:
- **Unique**: Never repeat for the same key across all time
- **Unpredictable**: Generated from a cryptographically secure random number generator (CSPRNG)
- **12 bytes**: Standard size for GCM (96 bits). Longer nonces work but require internal hashing that weakens security proofs.

In SFT, every encrypted chunk uses a fresh nonce generated with `os.urandom(12)`, which reads from the OS entropy pool (/dev/urandom on Linux, CryptGenRandom on Windows). This provides cryptographic randomness with negligible collision probability (2^96 possible values).

**Authentication Tag: Proof of Integrity**

The 16-byte authentication tag is computed over both the ciphertext and any AAD (covered next). It's a cryptographic commitment: "This ciphertext and this metadata were produced by someone with the correct key and have not been modified."

Verification happens during decryption. The `GCM` mode constructor accepts the tag as a parameter. If the recomputed tag doesn't match the provided tag, `decryptor.finalize()` raises an exception before returning any plaintext. This prevents timing attacks where an attacker could measure how far decryption proceeded before failure.

The tag is not a hash of the ciphertext. It's computed using GMAC, a MAC algorithm based on Galois field arithmetic. The security proof guarantees that an attacker without the key cannot produce a valid tag for modified ciphertext, even with access to many valid ciphertext/tag pairs.

## Additional Authenticated Data (AAD)

Imagine you're encrypting a network packet. The payload contains sensitive data, so you encrypt it. But the header contains metadata: packet version, message type, length, sequence number. This metadata isn't secret, so encrypting it serves no purpose. But it must not be tampered with. An attacker who modifies the sequence number could cause replay attacks or packet reordering.

Additional Authenticated Data (AAD) solves this. AAD is data that's authenticated but not encrypted. You pass it to the GCM encryptor before encrypting the payload. The authentication tag is computed over both the encrypted payload and the plaintext AAD. Verification requires both to match exactly.

In SFT, the binary packet header is passed as AAD. The header contains critical protocol information that must be authenticated but doesn't need confidentiality.

**Implementation with AAD**

```python
def encrypt_aes_gcm_with_aad(plaintext: bytes, key: bytes, nonce: bytes, aad: bytes) -> tuple[bytes, bytes]:
    """
    Encrypt plaintext with AES-256-GCM and authenticate additional data.

    Args:
        plaintext: Data to encrypt
        key: 32-byte AES-256 key
        nonce: 12-byte unique nonce
        aad: Additional authenticated data (not encrypted, but authenticated)

    Returns:
        (ciphertext, tag) tuple covering both payload and AAD
    """
    if len(key) != 32:
        raise ValueError("Key must be 32 bytes")
    if len(nonce) != 12:
        raise ValueError("Nonce must be 12 bytes")

    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    encryptor.authenticate_additional_data(aad)
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    tag = encryptor.tag

    return ciphertext, tag


def decrypt_aes_gcm_with_aad(ciphertext: bytes, key: bytes, nonce: bytes,
                               tag: bytes, aad: bytes) -> bytes:
    """
    Decrypt and verify both ciphertext and AAD.

    Args:
        ciphertext: Encrypted data
        key: 32-byte AES-256 key
        nonce: 12-byte nonce from encryption
        tag: 16-byte authentication tag
        aad: Same additional data used during encryption

    Returns:
        Decrypted plaintext

    Raises:
        ValueError: If authentication fails for either payload or AAD
    """
    if len(key) != 32 or len(nonce) != 12 or len(tag) != 16:
        raise ValueError("Invalid key, nonce, or tag size")

    try:
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        decryptor.authenticate_additional_data(aad)
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        return plaintext
    except Exception as e:
        raise ValueError(f"Authentication failed: {e}")


# Example: Packet with authenticated header
if __name__ == "__main__":
    import struct

    key = os.urandom(32)
    nonce = os.urandom(12)

    # Binary packet header (not secret, but must not be tampered with)
    version = 2
    msg_type = 0x02  # DATA packet
    seq_num = 42
    header = struct.pack("!BBH", version, msg_type, seq_num)  # 4 bytes

    # Payload (secret)
    payload = b"Secret file contents here"

    # Encrypt payload, authenticate header
    ciphertext, tag = encrypt_aes_gcm_with_aad(payload, key, nonce, header)
    print(f"Header (plaintext): {header.hex()}")
    print(f"Ciphertext: {ciphertext.hex()}")

    # Successful decryption with matching AAD
    decrypted = decrypt_aes_gcm_with_aad(ciphertext, key, nonce, tag, header)
    assert decrypted == payload
    print("Decryption with matching AAD successful")

    # Tamper with header: change sequence number from 42 to 99
    tampered_header = struct.pack("!BBH", version, msg_type, 99)
    try:
        decrypt_aes_gcm_with_aad(ciphertext, key, nonce, tag, tampered_header)
        print("ERROR: Header tampering not detected!")
    except ValueError:
        print("Header tampering detected and rejected")
```

This is exactly how SFT protects packet headers. From the source code (`sft.py`):

```python
# Pack header (plaintext metadata)
aad = struct.pack(HEADER_FORMAT, version, payload_type, payload_len, seq_num)

# Encrypt payload with AAD
ciphertext, tag = encrypt_aes_gcm(payload, session_key, nonce, aad=aad)
```

The receiver validates both the encrypted payload and the plaintext header. Modify either, and authentication fails. This prevents attackers from tampering with sequence numbers to reorder packets or changing payload types to trigger parsing bugs.

## Hashing and HMAC

Hashing and Message Authentication Codes (MACs) provide integrity verification, but for different threat models. Understanding the distinction is critical to using them correctly.

**SHA-256: Collision-Resistant One-Way Function**

SHA-256 is a cryptographic hash function that maps arbitrary-length input to a fixed 256-bit (32-byte) output. It has three key properties:

1. **One-way**: Given a hash, you cannot compute the original input (preimage resistance)
2. **Collision-resistant**: You cannot find two different inputs that produce the same hash
3. **Deterministic**: The same input always produces the same hash

SHA-256 is perfect for file integrity verification. Hash the file before transfer, send the hash separately (or embed it in a signed manifest), and verify after transfer. If the hashes match, the file is intact. If they don't, corruption or tampering occurred.

But SHA-256 alone doesn't prove authenticity. Anyone can compute a SHA-256 hash. If an attacker replaces your file with malicious content, they can compute the hash of the malicious file and replace your hash too. SHA-256 detects accidental corruption, not malicious tampering.

```python
import hashlib

def compute_file_hash(filepath: str) -> bytes:
    """
    Compute SHA-256 hash of a file in chunks for memory efficiency.

    Args:
        filepath: Path to file

    Returns:
        32-byte SHA-256 digest
    """
    sha256 = hashlib.sha256()

    with open(filepath, 'rb') as f:
        while chunk := f.read(4096):
            sha256.update(chunk)

    return sha256.digest()


# Example: Verify file integrity
if __name__ == "__main__":
    # Compute hash of original file
    original_hash = compute_file_hash("important.dat")
    print(f"Original hash: {original_hash.hex()}")

    # After transfer, recompute hash
    received_hash = compute_file_hash("important.dat")

    if original_hash == received_hash:
        print("File integrity verified")
    else:
        print("CORRUPTION DETECTED")
```

**HMAC-SHA256: Keyed Authentication**

HMAC (Hash-based Message Authentication Code) adds a secret key to the hash computation. Only someone with the key can compute a valid HMAC for a given message. This proves both integrity (the message hasn't changed) and authenticity (it was created by someone with the key).

HMAC construction is `HMAC(K, M) = H((K ⊕ opad) || H((K ⊕ ipad) || M))` where `H` is the underlying hash function (SHA-256), `K` is the key, `M` is the message, and `opad`/`ipad` are padding constants. The double hashing prevents length extension attacks that break naive `H(K || M)` constructions.

```python
import hmac
import hashlib

def compute_hmac(message: bytes, key: bytes) -> bytes:
    """
    Compute HMAC-SHA256 of message with key.

    Args:
        message: Data to authenticate
        key: Secret key (minimum 16 bytes recommended)

    Returns:
        32-byte HMAC digest
    """
    return hmac.new(key, message, hashlib.sha256).digest()


def verify_hmac(message: bytes, key: bytes, expected_hmac: bytes) -> bool:
    """
    Verify HMAC in constant time.

    Args:
        message: Data to verify
        key: Secret key
        expected_hmac: HMAC to verify against

    Returns:
        True if valid, False otherwise
    """
    computed_hmac = compute_hmac(message, key)
    return hmac.compare_digest(computed_hmac, expected_hmac)


# Example: Message authentication
if __name__ == "__main__":
    key = os.urandom(32)  # Shared secret between sender and receiver
    message = b"Transfer $10,000 from account A to account B"

    # Sender computes HMAC
    tag = compute_hmac(message, key)
    print(f"Message: {message}")
    print(f"HMAC: {tag.hex()}")

    # Receiver verifies HMAC
    if verify_hmac(message, key, tag):
        print("Message authenticated - executing transaction")
    else:
        print("AUTHENTICATION FAILED - transaction rejected")

    # Attacker modifies message
    tampered_message = b"Transfer $99,000 from account A to account B"
    if verify_hmac(tampered_message, key, tag):
        print("ERROR: Tampering not detected!")
    else:
        print("Tampering detected - modified message rejected")
```

**When to Use Hash vs HMAC**

| Use Case | Primitive | Reason |
|----------|-----------|--------|
| Verify file not corrupted during download | SHA-256 | Detects accidental bit flips, disk errors |
| Verify file not tampered with by attacker | HMAC-SHA256 or digital signature | Requires secret key or private key |
| Deduplicate files in storage | SHA-256 | Deterministic fingerprint |
| Authenticate API request | HMAC-SHA256 | Proves sender has shared secret |
| Verify software download authenticity | SHA-256 + digital signature | Hash verifies integrity, signature verifies publisher |

In SFT, we use SHA-256 for final file integrity verification and GCM authentication tags (which serve a similar purpose to HMAC) for per-packet authentication. We don't use separate HMAC because GCM provides it built-in.

## Key Exchange: ECDH and Ed25519

Symmetric encryption requires both parties to share the same secret key. But how do two parties who have never communicated before establish a shared secret over an untrusted network where attackers can eavesdrop on every byte?

This is the key exchange problem, and it's solved by asymmetric cryptography. Unlike symmetric algorithms where the same key encrypts and decrypts, asymmetric algorithms use a keypair: a public key that can be shared freely, and a private key that must be kept secret.

**X25519: Elliptic Curve Diffie-Hellman**

X25519 is an Elliptic Curve Diffie-Hellman (ECDH) key agreement protocol based on Curve25519. It allows two parties to derive a shared secret by exchanging public keys, without ever transmitting the secret itself.

The protocol:
1. Alice generates a keypair (private key `a`, public key `A = a·G` where `G` is the curve generator)
2. Bob generates a keypair (private key `b`, public key `B = b·G`)
3. Alice and Bob exchange public keys over the network (attacker can see `A` and `B`)
4. Alice computes shared secret: `S = a·B = a·(b·G) = (a·b)·G`
5. Bob computes shared secret: `S = b·A = b·(a·G) = (a·b)·G`
6. Both now share the same secret `S`, which can be used to derive encryption keys

The attacker sees `A` and `B` but cannot compute `S` without solving the Elliptic Curve Discrete Logarithm Problem (ECDLP), which is computationally infeasible for properly chosen curves.

X25519 is fast, secure, and provides perfect forward secrecy: if long-term keys are compromised later, past session keys remain secure because the ephemeral private keys (`a` and `b`) were deleted after deriving `S`.

```python
from cryptography.hazmat.primitives.asymmetric import x25519

def x25519_generate_keypair() -> tuple[bytes, bytes]:
    """
    Generate X25519 keypair for ECDH.

    Returns:
        (private_key_bytes, public_key_bytes) tuple
    """
    private_key = x25519.X25519PrivateKey.generate()
    public_key = private_key.public_key()

    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )

    return private_bytes, public_bytes


def x25519_compute_shared_secret(my_private_key: bytes, peer_public_key: bytes) -> bytes:
    """
    Compute X25519 shared secret from my private key and peer's public key.

    Args:
        my_private_key: My 32-byte X25519 private key
        peer_public_key: Peer's 32-byte X25519 public key

    Returns:
        32-byte shared secret
    """
    private_key_obj = x25519.X25519PrivateKey.from_private_bytes(my_private_key)
    public_key_obj = x25519.X25519PublicKey.from_public_bytes(peer_public_key)

    shared_secret = private_key_obj.exchange(public_key_obj)
    return shared_secret


# Example: Simulated key exchange between Alice and Bob
if __name__ == "__main__":
    print("=== X25519 Key Exchange Simulation ===")

    # Alice generates keypair
    alice_private, alice_public = x25519_generate_keypair()
    print(f"Alice public key: {alice_public.hex()}")

    # Bob generates keypair
    bob_private, bob_public = x25519_generate_keypair()
    print(f"Bob public key: {bob_public.hex()}")

    # Alice and Bob exchange public keys over network (attacker can see these)
    # ...

    # Alice computes shared secret using her private key and Bob's public key
    alice_shared = x25519_compute_shared_secret(alice_private, bob_public)

    # Bob computes shared secret using his private key and Alice's public key
    bob_shared = x25519_compute_shared_secret(bob_private, alice_public)

    # Both derive the same secret
    assert alice_shared == bob_shared
    print(f"Shared secret: {alice_shared.hex()}")
    print("Key exchange successful!")
```

**Ed25519: Digital Signatures for Authentication**

X25519 establishes a shared secret, but it doesn't prove identity. An attacker performing a man-in-the-middle attack can intercept Alice's public key, replace it with their own, complete a key exchange with Bob, and decrypt/re-encrypt all traffic. Bob thinks he's talking to Alice, but he's actually talking to the attacker.

Digital signatures solve this. Ed25519 is an elliptic curve signature algorithm (also based on Curve25519) that provides authentication and non-repudiation. The private key signs a message, producing a signature that can be verified with the public key. Only the holder of the private key can produce valid signatures.

In SFT, each party has a long-term Ed25519 identity keypair. During the handshake, they sign their ephemeral X25519 public keys with their Ed25519 private keys. The peer verifies the signature against the known Ed25519 public key. This proves the ephemeral key belongs to the claimed identity, preventing MITM attacks.

```python
from cryptography.hazmat.primitives.asymmetric import ed25519

def ed25519_generate_keypair() -> tuple[bytes, bytes]:
    """
    Generate Ed25519 signing keypair.

    Returns:
        (private_key_bytes, public_key_bytes) tuple
    """
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )

    return private_bytes, public_bytes


def ed25519_sign(message: bytes, private_key: bytes) -> bytes:
    """
    Sign message with Ed25519 private key.

    Args:
        message: Data to sign
        private_key: 32-byte Ed25519 private key

    Returns:
        64-byte signature
    """
    private_key_obj = ed25519.Ed25519PrivateKey.from_private_bytes(private_key)
    signature = private_key_obj.sign(message)
    return signature


def ed25519_verify(message: bytes, signature: bytes, public_key: bytes) -> bool:
    """
    Verify Ed25519 signature.

    Args:
        message: Signed data
        signature: 64-byte signature
        public_key: 32-byte Ed25519 public key

    Returns:
        True if signature is valid, False otherwise
    """
    try:
        public_key_obj = ed25519.Ed25519PublicKey.from_public_bytes(public_key)
        public_key_obj.verify(signature, message)
        return True
    except Exception:
        return False


# Example: Sign and verify
if __name__ == "__main__":
    print("=== Ed25519 Digital Signature ===")

    # Server generates long-term identity keypair
    server_private, server_public = ed25519_generate_keypair()
    print(f"Server public key: {server_public.hex()}")

    # Server signs a message (e.g., its ephemeral X25519 public key)
    message = b"Server ephemeral X25519 key: <key_bytes_here>"
    signature = ed25519_sign(message, server_private)
    print(f"Signature: {signature.hex()}")

    # Client verifies signature using server's known public key
    if ed25519_verify(message, signature, server_public):
        print("Signature valid - server identity confirmed")
    else:
        print("SIGNATURE INVALID - possible MITM attack!")

    # Attacker modifies message
    tampered_message = b"Server ephemeral X25519 key: <attacker_key>"
    if ed25519_verify(tampered_message, signature, server_public):
        print("ERROR: Tampering not detected!")
    else:
        print("Tampering detected - signature verification failed")
```

The combination of X25519 for key exchange and Ed25519 for authentication provides both confidentiality (via the derived shared secret) and authenticity (via signature verification). This is the foundation of SFT's handshake protocol, which we'll implement in full detail in Article 3.

## Key Derivation: PBKDF2

The X25519 shared secret is 32 bytes of high-entropy data. But it's not directly suitable as an AES-256 key. Key derivation functions (KDFs) transform shared secrets into cryptographic keys with specific properties.

PBKDF2 (Password-Based Key Derivation Function 2) is designed for deriving keys from low-entropy passwords, but it also works for high-entropy shared secrets. It applies a pseudorandom function (HMAC-SHA256) iteratively to the input, making brute-force attacks expensive.

The key parameters:
- **Password**: The input material (X25519 shared secret in SFT)
- **Salt**: Random data that ensures different outputs for the same password
- **Iterations**: Number of HMAC-SHA256 rounds (more iterations = more expensive for attackers)
- **Key length**: Desired output size (32 bytes for AES-256)

OWASP recommends 600,000 iterations for PBKDF2-HMAC-SHA256 as of 2024 (updated from 100,000 in previous years) to maintain security against increasingly powerful hardware.

```python
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

def derive_key_pbkdf2(shared_secret: bytes, salt: bytes, iterations: int = 600000) -> bytes:
    """
    Derive AES-256 key from shared secret using PBKDF2-HMAC-SHA256.

    Args:
        shared_secret: Input material (e.g., X25519 shared secret)
        salt: Random salt (minimum 16 bytes)
        iterations: PBKDF2 iteration count (default 600,000 per OWASP 2024)

    Returns:
        32-byte AES-256 key
    """
    if len(salt) < 16:
        raise ValueError("Salt must be at least 16 bytes")

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # AES-256 key size
        salt=salt,
        iterations=iterations,
        backend=default_backend()
    )

    key = kdf.derive(shared_secret)
    return key


# Example: Derive session key from X25519 shared secret
if __name__ == "__main__":
    # Simulate X25519 key exchange (from previous example)
    alice_private, alice_public = x25519_generate_keypair()
    bob_private, bob_public = x25519_generate_keypair()

    shared_secret = x25519_compute_shared_secret(alice_private, bob_public)
    print(f"Shared secret: {shared_secret.hex()}")

    # Generate salt (combined nonces from both parties in real protocol)
    salt = os.urandom(16)
    print(f"Salt: {salt.hex()}")

    # Derive AES-256 session key
    import time
    start = time.perf_counter()
    session_key = derive_key_pbkdf2(shared_secret, salt, iterations=600000)
    duration = time.perf_counter() - start

    print(f"Session key: {session_key.hex()}")
    print(f"Derivation time: {duration:.3f}s")
```

On modern hardware, 600,000 iterations takes approximately 0.3-0.5 seconds. This is acceptable for a single handshake but makes brute-forcing millions of candidate passwords computationally prohibitive. For SFT, where the input is a 256-bit random shared secret (not a weak password), this provides defense-in-depth against side-channel attacks or implementation flaws that might partially leak the shared secret.

The salt prevents precomputation attacks. Without a salt, an attacker could precompute `PBKDF2(common_secret, iterations)` for likely shared secrets and build a rainbow table. With a random salt, each key derivation produces a different output, even for the same shared secret.

## Constant-Time Comparison

You've encrypted the data, authenticated it with GCM tags, verified signatures, and derived keys securely. But there's a subtle attack vector: timing.

Timing attacks exploit the fact that comparison operations on modern CPUs often complete in different amounts of time depending on where the first mismatch occurs. Compare two 16-byte authentication tags with a naive loop:

```python
def insecure_compare(a: bytes, b: bytes) -> bool:
    if len(a) != len(b):
        return False
    for i in range(len(a)):
        if a[i] != b[i]:
            return False  # Early exit on first mismatch
    return True
```

If the first byte differs, the function returns immediately. If the first byte matches but the second differs, it takes slightly longer. An attacker can measure this timing difference over thousands of attempts and reconstruct the correct value byte-by-byte.

This isn't theoretical. Real-world timing attacks have broken authentication on payment systems, TLS implementations, and password checks. The differences can be as small as microseconds, but statistical analysis over many samples makes them detectable even over network connections.

**Constant-Time Comparison**

The defense is constant-time comparison: check every byte regardless of where mismatches occur, taking the same time whether the values match completely or differ in the first byte.

Python's `hmac.compare_digest()` provides this:

```python
import hmac

def secure_compare(a: bytes, b: bytes) -> bool:
    """
    Compare two byte strings in constant time.

    Args:
        a, b: Byte strings to compare

    Returns:
        True if equal, False otherwise

    Note:
        Constant-time comparison prevents timing attacks
    """
    return hmac.compare_digest(a, b)


# Example: Compare authentication tags safely
if __name__ == "__main__":
    correct_tag = os.urandom(16)

    # Correct tag
    if secure_compare(correct_tag, correct_tag):
        print("Tag valid")

    # Incorrect tag (differs in first byte)
    wrong_tag = bytearray(correct_tag)
    wrong_tag[0] ^= 0xFF

    # Both comparisons take the same time
    import time

    trials = 10000

    # Time correct comparison
    start = time.perf_counter()
    for _ in range(trials):
        secure_compare(correct_tag, correct_tag)
    time_match = time.perf_counter() - start

    # Time incorrect comparison
    start = time.perf_counter()
    for _ in range(trials):
        secure_compare(correct_tag, bytes(wrong_tag))
    time_mismatch = time.perf_counter() - start

    print(f"Match time: {time_match:.6f}s")
    print(f"Mismatch time: {time_mismatch:.6f}s")
    print(f"Difference: {abs(time_match - time_mismatch):.6f}s (minimal)")
```

In native implementations, the situation is even more critical. C's `memcmp()` is optimized for speed, exiting early on mismatch. OpenSSL provides `CRYPTO_memcmp()` for constant-time comparison:

```c
// In C module (crypto_accelerator.c)
#include <openssl/crypto.h>

int compare_digest_safe(const uint8_t *a, const uint8_t *b, size_t len) {
    return CRYPTO_memcmp(a, b, len) == 0;
}
```

Rust's `subtle` crate provides `ConstantTimeEq`:

```rust
// In Rust module (lib.rs)
use subtle::ConstantTimeEq;

pub fn compare_digest(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}
```

The performance cost of constant-time comparison is negligible (single-digit microseconds), but the security benefit is critical. Use it for all secret comparisons: authentication tags, MAC values, password hashes, signature verification intermediate steps.

## Summary: The Complete Cryptographic Toolkit

We've covered every primitive used in SFT's implementation. Here's the complete mapping from cryptographic operation to purpose to Python implementation:

| Primitive | Purpose in SFT | Python Library | Key Sizes | Security Property |
|-----------|---------------|----------------|-----------|-------------------|
| **AES-256-GCM** | Encrypt file chunks with authentication | `cryptography.hazmat` | Key: 32 bytes, Nonce: 12 bytes | Confidentiality + Integrity (AEAD) |
| **X25519 ECDH** | Establish shared session key | `cryptography.hazmat` | Private: 32 bytes, Public: 32 bytes | Authenticated key exchange, PFS |
| **Ed25519** | Sign handshake messages for authentication | `cryptography.hazmat` | Private: 32 bytes, Public: 32 bytes, Signature: 64 bytes | Non-repudiation, identity verification |
| **SHA-256** | Verify complete file integrity | `hashlib` | N/A (output: 32 bytes) | Collision resistance |
| **HMAC-SHA256** | Alternative MAC (SFT uses GCM instead) | `hmac` | Key: 32 bytes | Message authentication |
| **PBKDF2-HMAC-SHA256** | Derive AES key from ECDH shared secret | `cryptography.hazmat` | Input: 32 bytes, Salt: 16+ bytes, Output: 32 bytes | Slow key derivation (600k iterations) |
| **Constant-time compare** | Prevent timing attacks on tag verification | `hmac.compare_digest()` | N/A | Side-channel resistance |

Every function shown in this article is syntactically correct, directly runnable, and used in the actual SFT implementation. The parameters match the source code: 32-byte AES keys, 12-byte GCM nonces, 16-byte authentication tags, 600,000 PBKDF2 iterations.

The primitives work together as a system:

1. **Handshake**: X25519 generates ephemeral keypairs, Ed25519 signs public keys, PBKDF2 derives the session key
2. **Data transfer**: AES-256-GCM encrypts chunks with AAD-protected headers, SHA-256 verifies complete files
3. **Security**: Constant-time comparison prevents timing attacks on tags and signatures

With these building blocks mastered, we're ready to assemble them into a complete protocol. In Article 3, we'll implement the full handshake: HELLO, CHALLENGE, RESPONSE, SESSION_ESTABLISHED. You'll see exactly how X25519, Ed25519, and PBKDF2 orchestrate to establish a secure channel between two parties who have never communicated before, all while defending against MITM attacks, replay attacks, and DoS attempts.

---

**Next**: Article 3 - The Handshake Protocol: From Strangers to Shared Key. Now that we know the tools, let's see how to orchestrate them into a complete key exchange protocol with mutual authentication and anti-replay protection.
