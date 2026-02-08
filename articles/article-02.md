---

Cryptographic Foundations: The Building Blocks of Secure Communication
When Theory Meets Implementation
After establishing why secure file transfer is hard, it's time to open the toolbox. This article covers the cryptographic primitives that make SFT work - not just what they are, but why they're designed this way and how they fit together.
No theory without practice. Every concept comes with code.

---

AES-256-GCM: One Operation, Two Guarantees
AES (Advanced Encryption Standard) is just a block cipher - it transforms 16 bytes using a key. To encrypt arbitrary data, you wrap it in a mode of operation. The mode you choose determines the security properties you get.
I chose GCM (Galois/Counter Mode) because it provides authenticated encryption in a single operation. You don't just get encryption - you get a cryptographic proof that nothing was tampered with.
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
# Encryption
cipher = AESGCM(key)  # 32-byte key for AES-256
nonce = os.urandom(12)  # Must be unique per encryption
ciphertext = cipher.encrypt(nonce, plaintext, associated_data)
# Decryption (raises exception if anything is wrong)
plaintext = cipher.decrypt(nonce, ciphertext, associated_data)
The associated_data parameter is powerful. In SFT, packet headers are authenticated but not encrypted-preventing an attacker from tampering with sequence numbers or message types while keeping the actual file data confidential.

---

X25519 & Ed25519: The Elliptic Curve Duo
Modern cryptography has largely moved from RSA to elliptic curves. SFT uses two curves from the Curve25519 family.
X25519 performs Diffie-Hellman key exchange. Both parties generate ephemeral keypairs, exchange public keys, and independently compute the same shared secret.
from cryptography.hazmat.primitives.asymmetric import x25519
# Generate ephemeral keypair
private_key = x25519.X25519PrivateKey.generate()
public_key = private_key.public_key()
# Exchange public keys with peer, then compute shared secret
shared_secret = private_key.exchange(peer_public_key)  # 32 bytes
Using ephemeral keys means every session gets a unique secret. Even if an attacker records all traffic and later compromises long-term keys, they can't decrypt past sessions. This is forward secrecy.
The computational cost is symmetric - client and server do equal work. No more RSA exhaustion attacks.
Ed25519: Digital Signatures
Ed25519 proves identity. Each party has a long-term Ed25519 keypair. During handshake, they sign the transcript, proving possession of the private key.
from cryptography.hazmat.primitives.asymmetric import ed25519
# Generate long-term identity keypair (done once, stored securely)
identity_private = ed25519.Ed25519PrivateKey.generate()
identity_public = identity_private.public_key()
# Sign handshake transcript
transcript = client_hello + server_hello + ephemeral_keys
signature = identity_private.sign(transcript)
# Verify signature
try:
    peer_identity_public.verify(signature, transcript)
    # Good! Authenticated peer
except InvalidSignature:
    # ABORT! Possible MITM attack
    connection.close()
One bug I hit: not validating received public keys before use. The penetration test caught this immediately. An attacker could send malformed 32-byte keys that passed length checks but had weak mathematical properties.
The fix requires explicit validation:
def validate_x25519_public_key(key_bytes):
    if len(key_bytes) != 32:
        raise ValueError("X25519 public key must be 32 bytes")
    
    # Check for weak points (all zeros, order of base point, etc.)
    WEAK_POINTS = [
        bytes(32),  # All zeros
        b'\x01' + bytes(31),  # Order 1
        # ... other known weak points
    ]
    
    if key_bytes in WEAK_POINTS:
        raise ValueError("Weak X25519 public key rejected")
    
    # Verify it loads correctly
    try:
        x25519.X25519PublicKey.from_public_bytes(key_bytes)
    except Exception:
        raise ValueError("Invalid X25519 public key structure")
Never trust user input, even cryptographic keys.

---

PBKDF2: From Shared Secret to Session Key
The X25519 exchange gives you a 32-byte shared secret. But you shouldn't use it directly as your AES key. Why? That raw secret might have low entropy in edge cases or exploitable mathematical structure.
Process it through a key derivation function (KDF):
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,  # AES-256 key
    salt=session_salt,  # Unique per session
    iterations=600000,  # OWASP 2024 recommendation
)
session_key = kdf.derive(shared_secret)
This stretches the shared secret through 600,000 iterations of HMAC-SHA256, mixing in a unique salt. The output is uniformly random key material suitable for AES-256.
Why 600,000 iterations? Updated from 100,000 based on OWASP 2024 recommendations. It's a balance - too few allows brute-forcing weak secrets, too many wastes CPU during legitimate handshakes.

---

Additional Authenticated Data (AAD)
One of the most important features in SFT's protocol is AAD usage with AES-GCM.
The problem: You need to authenticate packet headers (sequence number, message type, length) without encrypting them because you need to read the header to know what to do with the packet.
GCM's solution: Additional Authenticated Data. This data is included in the authentication tag calculation but not encrypted.
# Packet structure: header + encrypted_payload + tag
header = struct.pack('!BIH', msg_type, sequence_number, payload_length)
# Encrypt with AAD
nonce = os.urandom(12)
ciphertext = cipher.encrypt(
    nonce,
    plaintext,
    associated_data=header  # Authenticated but not encrypted
)
# Send: header + nonce + ciphertext (which includes the tag)
An attacker can read the header but can't modify it without breaking authentication. This prevents sequence number manipulation, message type confusion, and length tampering attacks.

---

The Complete Stack
After months of development, testing, and security fixes, the cryptographic foundation stabilized into a coherent system:
AES-256-GCM handles authenticated encryption with 256-bit keys (32 bytes). Every file chunk is encrypted and authenticated in a single operation.
X25519 performs ephemeral key exchange using 256-bit elliptic curve keys (32 bytes). Each session generates fresh keypairs, ensuring forward secrecy.
Ed25519 provides digital signatures with 256-bit keys (32 bytes). Long-term identity keys prove who you're talking to and prevent man-in-the-middle attacks.
PBKDF2-HMAC-SHA256 derives session keys from the shared secret, stretching it through 600,000 iterations to ensure uniformly random key material.
SHA-256 produces 256-bit hashes for file integrity verification, ensuring the received file matches what was sent.
os.urandom and secrets provide cryptographically secure random number generation for nonces, salts, and key material - pulling from the operating system's CSPRNG.

Each primitive does one thing well. They compose cleanly. And critically, they're all well-studied, widely-implemented standards - no custom cryptography.

---

The Real Lesson
The biggest takeaway from this phase wasn't about any individual algorithm. It was about the gap between theory and practice.
Implementation details matter. Every choice has consequences. Every shortcut creates vulnerabilities.

---

What's Next
The cryptographic building blocks are in place. We understand their properties and their limitations.
In the next article, we'll see these pieces come together in the handshake protocol. We'll trace a connection from first TCP byte to established secure session - every message, every signature, every decision point.
This is where the real complexity lives. Not in the crypto itself, but in getting all the details right.

---

Next in the series: The Handshake Protocol: Establishing Trust Over Hostile Networks