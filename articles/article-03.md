---

The Handshake Protocol: Establishing Trust Over Hostile Networks
A Conversation Between Strangers
Picture this: two computers have never communicated before. They need to establish a shared secret and prove their identities - all while assuming someone is actively watching and potentially interfering with every byte they exchange.
This is the handshake problem. It's a carefully choreographed dance where one misstep means total failure.
In the previous articles, we covered the cryptographic primitives - AES-GCM, X25519, Ed25519, PBKDF2. Now those pieces come together into an actual protocol. This is where theory becomes implementation, and where I learned that "working code" and "correct protocol" are two very different things.
The handshake looked elegant on paper. In practice, I hit three critical bugs in the first four days. Let me walk you through what happened.

---

The Protocol: Step by Step
Here's the complete handshake sequence SFT implements:
1. TCP connection established
2. Server generates ephemeral X25519 keypair
 Fresh keys for this session only. Forward secrecy starts here.
3. Server sends: ephemeral_public + identity_public (64 bytes total)
 No encryption yet - there's no shared secret to encrypt with. These are sent in plaintext.
4. Client validates keys against known weak points
 All-zero keys, order-1 points, and other mathematically weak values are rejected immediately. This validation caught an actual attack during penetration testing.
5. Client generates its own ephemeral keypair
6. Client computes shared_secret via X25519 Diffie-Hellman
 Using the server's ephemeral public key and its own ephemeral private key.
7. Client signs the full transcript
 The signature covers both ephemeral keys, binding the client's identity to this specific exchange. An attacker can't replay old signatures because the ephemeral keys change every session.
8. Client sends: ephemeral_public + signature
9. Server verifies signature
 Confirms the client possesses the private key corresponding to their claimed identity.
10. Server computes the same shared_secret independently
 Using the client's ephemeral public key and its own ephemeral private key. Both parties now have identical 32-byte secrets.
11. Both derive session_key via PBKDF2
 The raw shared secret goes through 600,000 iterations of HMAC-SHA256 to produce 64 bytes: 32 for HMAC authentication, 32 for AES-256 encryption.
12. Encrypted communication begins
If any step fails - signature verification, key validation, secret derivation - the connection aborts immediately. No partial states. No fallback negotiation. No second chances.
That's the theory. The implementation is where things got interesting.

---

Bug #1: The Double Handshake (October 28th)
The first bug appeared within hours of the initial commit.
The client was performing the handshake twice. Once correctly in connect_to_server(), then accidentally a second time by calling _handle_connection()-which is actually the server's method.
The sequence looked like this:
1. Client initiates handshake → Success
2. Server expects encrypted data
3. Client sends another handshake
4. Server tries to decrypt handshake bytes as AES-GCM ciphertext
5. Instant desynchronization and crash

The root cause? Poor separation of concerns. The handshake logic and the message loop were tangled together in a way that allowed the client to inadvertently run server code.
The fix required strict protocol phase separation:
Handshake happens in connect_to_server() (client) or _handle_connection() (server)
Message loop starts in _handle_messages()
Two phases, two functions, zero overlap

Simple in retrospect. Obvious, even. But when you're deep in cryptographic details, these architectural mistakes slip through.

---

Bug #2: Key ID Not Found (October 28th)
The handshake completed successfully. Signatures verified. Shared secrets computed. Everything looked perfect.
Then the first encrypted message failed with "Key ID not found."
Both parties performed the X25519 exchange correctly and arrived at the same 32-byte shared secret. I confirmed this with debug logging. The secret matched byte-for-byte on both sides.
So why couldn't they decrypt each other's messages?
The bug was subtle: after deriving the shared secret, both parties called generate_session_key(), which created a brand new random key. The shared secret was computed correctly and then immediately discarded.
Here's what was happening:
python
# Both parties compute the same shared_secret
shared_secret = private_key.exchange(peer_public_key)
# Then both throw it away and generate random keys
session_key = secrets.token_bytes(32)  # WRONG!
# Now they have different keys

The fix made key derivation deterministic:
python
# Derive session key from shared secret
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=64,  # 32 bytes HMAC + 32 bytes AES
    salt=session_salt,
    iterations=600000,
)
key_material = kdf.derive(shared_secret)
hmac_key = key_material[:32]
aes_key = key_material[32:64]
key_id = hashlib.sha256(aes_key).digest()[:16]

Now both parties derive identical keys from identical inputs. The shared secret actually becomes the session key. Revolutionary, I know.
This bug survived my initial tests because I was only testing the handshake in isolation, not the subsequent encrypted message exchange. Integration testing caught it.

---

Bug #3: The Race Condition (October 29th)
This one was more insidious.
The server stored peer connection state as instance variables: self.peer_socket, self.peer_address. Seemed reasonable-until two clients connected simultaneously.
Here's what happened:
Thread 1 starts handshake with Client A, stores self.peer_socket = socket_A
Thread 2 starts handshake with Client B, overwrites self.peer_socket = socket_B
Thread 1 tries to send data, reads self.peer_socket, gets socket_B
Thread 1 sends Client A's data to Client B's connection
Both clients receive corrupted data and crash

Classic race condition. The kind that only manifests under specific timing conditions and is hell to debug.
The fix: stop sharing state across threads. Pass sockets as local function arguments instead of instance variables.
python
# Before (WRONG)
def _handle_connection(self):
    self.peer_socket, self.peer_address = self.server_socket.accept()
    # Now self.peer_socket is shared across all threads
# After (CORRECT)
def _handle_connection(self):
    peer_socket, peer_address = self.server_socket.accept()
    # socket is local to this thread
    self._handle_client(peer_socket, peer_address)

Basic concurrency hygiene. But easy to miss when you're focused on getting the cryptography right and not thinking about multithreading edge cases.
The lesson? Security bugs aren't always in the crypto. Sometimes they're in the boring parts - thread safety, state management, error handling. These matter just as much.

---

Replay Protection: Defense in Depth
The handshake itself resists replay attacks because every session uses fresh ephemeral keys. An attacker who records a complete handshake can't replay it later - the server will generate different ephemeral keys next time, producing a different shared secret.
But what about replaying individual messages within an established session?
That requires per-message protection: every encrypted message carries a monotonically increasing sequence number, authenticated as part of the GCM ciphertext.
python
# Send side
sequence_number = self.next_sequence()
header = struct.pack('!I', sequence_number)
ciphertext = cipher.encrypt(nonce, plaintext, associated_data=header)
# Receive side
if sequence_number <= self.last_seen_sequence:
    connection.close()  # Replay detected
    return
if sequence_number in self.seen_sequences:
    connection.close()  # Duplicate detected
    return
self.seen_sequences.add(sequence_number)
self.last_seen_sequence = sequence_number

The receiver tracks a sliding window of seen sequence numbers using a bounded set (maximum 10,000 entries). When it fills, the oldest entries are dropped - preventing unbounded memory growth during long-running sessions.
This two-layer approach - ephemeral handshakes plus per-message sequence numbers - makes replay attacks computationally infeasible.

---

Testing: Beyond Unit Tests
Unit tests verify individual functions. Cryptographic protocols fail at the integration layer.
My test suite evolved to cover three distinct levels:
Level 1: Cryptographic correctness
 Simulate the mathematical handshake without sockets. Generate keypairs, compute shared secrets, verify both parties arrive at identical keys. Pure crypto, no network.
Level 2: End-to-end integration
 Spin up a real server thread, connect a real client, perform the actual handshake over TCP, verify encrypted communication works. Full stack, happy path.
Level 3: Adversarial scenarios
 Intentionally send weak keys, replayed signatures, malformed messages, out-of-order packets. The server must reject all of them gracefully without crashing or leaking information.
The adversarial tests are what caught the weak key validation bug before it reached any users. They simulate what a real attacker would try - all-zero keys, small-order points, invalid signature formats - and verify the protocol responds correctly.
Here's a key insight: you need to test failure modes as rigorously as success modes. A protocol that crashes on malformed input is a security vulnerability.

---

What Actually Matters
Building the handshake taught me something important: the hard part of security engineering isn't the cryptography itself. The primitives are well-defined. The math works.
The hard part is getting all the details right.
Separating protocol phases cleanly so you don't accidentally run server code on the client
Deriving keys deterministically so both parties actually end up with the same secret
Managing thread safety so concurrent connections don't corrupt each other's state
Validating inputs before cryptographic operations so attackers can't send weak keys
Testing adversarially so bugs get caught before deployment

None of these are glamorous. None of them involve advanced mathematics or exotic algorithms. But each one is critical.
Security is built from a thousand small decisions. Get one wrong and the whole system falls apart.

---

What's Next
We have a secure channel. Both parties share a session key and have proven their identities. Now we can transfer data.
But encrypting a file isn't as simple as "read file, encrypt, send." You need efficient chunking for large files, per-chunk authentication to detect corruption mid-transfer, resume capability for interrupted transfers, and error handling for the many ways networks fail.
In the next article, we'll build the encryption pipeline: from plaintext on disk to encrypted chunks on the wire to verified file on the receiver. This is where performance starts to matter, and where the native C and Rust accelerators become essential.

---

Next in the series: The Encryption Pipeline: From File to Wire and Back Again