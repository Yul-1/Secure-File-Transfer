---

Why Secure File Transfer is Harder Than It Looks
When "Just Send the File" Goes Horribly Wrong
It was late October 2025, and I found myself staring at a terminal, about to transfer a file across the network. A simple task I'd done thousands of times before. SFTP, SCP, rsync over SSH - we use these tools daily without thinking twice.
But this time I stopped and asked myself: What's actually happening here?
I knew the surface-level answer: "SSH uses encryption" and "TLS guarantees integrity." But that wasn't enough anymore. I didn't just want to use secure channels. I wanted to understand them. Really understand them. The kind of understanding that only comes from getting your hands dirty and building something from scratch.
On October 28th, 2025, I created the first commit of what would become the Secure File Transfer project. The goal was ambitious: implement a complete secure file transfer system with end-to-end encryption, replay attack protection, and native acceleration in C and Rust.
Not to replace OpenSSH. Not to build something "better" than decades of battle-tested software. But to learn what secure really means.
This is the story of that journey - and why transferring a file securely is far more complex than it appears.

---

The Illusion of Simplicity
Here's what transferring a file looks like:
1. Open a TCP connection
2. Read file in chunks
3. Send bytes over the wire
4. Close connection
5. Done
Simple, right? This is the mental model most developers carry. And it works fine - until you introduce an adversary.
Imagine a realistic scenario: you need to send a confidential document to a colleague across the Internet. Between you and them sit routers, switches, ISPs, coffee shop Wi-Fi networks, corporate proxies. The network is hostile territory.
What could go wrong?
An attacker sitting on the network path could:
Read everything (confidentiality breach)
Modify the data without detection (integrity violation)
Impersonate the server and steal your file (authentication failure)
Capture and replay old messages later (replay attack)
Overwhelm the server with fake handshakes (availability attack)

These aren't hypothetical scenarios from academic papers. They're documented, real-world attack patterns that have compromised systems for decades.
And each one requires a specific, carefully-designed countermeasure.

---

The CIA Triad: What Security Actually Means
In information security, there's a fundamental framework called the CIA triad. Not the intelligence agency - Confidentiality, Integrity, and Availability. These three pillars define what it means for a system to be secure.
Confidentiality: Keeping Secrets Secret
Only authorized parties should be able to read the data. This is the obvious one everyone thinks about first.
For SFT, I chose AES-256-GCM for symmetric encryption. Not just AES in any mode - specifically GCM (Galois/Counter Mode). Here's why: GCM provides both encryption and authentication in a single operation. It generates an authentication tag that cryptographically proves the ciphertext hasn't been tampered with.
Integrity: Detecting Tampering
Data integrity means you can detect if anything was modified in transit - even a single bit flip.
AES-GCM already provides this through its authentication tag, but I added an additional layer: Additional Authenticated Data (AAD). The packet headers are authenticated but not encrypted. This prevents an attacker from tampering with metadata like sequence numbers or packet types while still keeping the actual file data confidential.
Why does this matter? Without AAD, an attacker could flip bits in the header to manipulate sequence numbers, potentially bypassing replay protection or causing denial of service.
Availability: Staying Online Under Attack
Security isn't just about protecting data - it's about keeping the service functional even when someone's trying to break it.
This is where protocol design choices become critical. I chose ECDH (Elliptic Curve Diffie-Hellman) for key exchange instead of RSA for a specific reason: computational asymmetry.
With RSA, an attacker can send thousands of connection requests, forcing the server to perform expensive RSA operations for each one. It's a classic CPU exhaustion attack. ECDH operations are significantly lighter and more balanced between client and server, making this attack vector much harder to exploit.

---

A Layered Architecture: Solving the Performance-Security Tension
From day one, I knew I wanted a layered system. Not just for code organization, but to solve a fundamental tension in cryptographic software: security versus performance.
The architecture has three distinct layers:
Protocol Layer: Handles all network logic, message framing, state machines
Wrapper Layer: Provides a uniform cryptographic interface with automatic fallback to pure Python if native modules fail to compile
Core Layer: Uses OpenSSL (via C) or ring/chacha20poly1305 (via Rust) to accelerate critical operations

Why this split between Python and native code?
Python gives you rapid development and readability. The protocol logic is complex enough without fighting with manual memory management or segfaults during development.
Native code gives you performance where it matters. Encrypting a 500MB file in pure Python can take several seconds. With an optimized C or Rust module, you're down to milliseconds.
Initially, there was only the C implementation using OpenSSL. In December, I added Rust, and it was eye-opening.
In C, you manually manage malloc, free, and secure key cleanup. One mistake-forgetting to zero memory before freeing it, for example-and you've potentially leaked key material. Rust eliminates these bug classes at compile time through its ownership system. The compiler literally won't let you make certain categories of memory safety errors.
It was illuminating to see the Rust compiler block a bug that would have silently passed in C and only been caught during a security audit (if at all).

---

More Questions Than Answers
When I made that first commit, I was operating mostly on intuition. I'd read papers. But I had no practical experience implementing cryptographic protocols.
The questions kept piling up:
How do you implement a secure handshake from scratch?
How do you handle replay protection without unbounded memory growth?
How do you balance security and performance?
How do you test a cryptographic system? Unit tests aren't enough, but what else?

The only way to find answers was to build it piece by piece, fail, fix, and test again.
And fail I did.
The first week was a productive disaster:
October 28th: First working commit
October 29th: Five indentation fixes, client/server crashes, accidental double handshake
October 30th: 27/27 tests passing. I thought I was done.
November 2nd: Penetration testing. Twelve critical vulnerabilities found.

The bugs were humbling:
Using random instead of os.urandom for nonce generation-a non-cryptographically-secure PRNG
Race conditions in multithreaded key management
An attacker could fill the replay protection queue with fake session IDs, then replay old messages
Weak validation of received public keys during handshake

All my tests passed. The code ran. But the system wasn't secure.
This taught me the most important lesson of the entire project: test coverage doesn't equal security. You need adversarial thinking - actually trying to break your own system - to find the bugs that matter.

---

A Critical Disclaimer: Education, Not Production
Before we go further, I need to be absolutely clear about something:
This project is educational. It is not production-ready without external audit.
The concepts are sound. The code works. The tests pass. The penetration test found and fixed those twelve bugs. But a production-grade cryptographic system requires years of public scrutiny, formal security audits, extensive fuzzing, and expert review.
OpenSSH has this validation. TLS has this validation. My project does not.
If you need to transfer sensitive files in production, use SSH, SFTP, or TLS. Use mature tools that have been tested, broken, fixed, and hardened by expert teams over decades.
But if you want to understand how these tools work - if you want to grasp what happens between typing scp file.txt server: and the file appearing on the remote machine-then this journey is for you.
Implementing cryptographic protocols using standard, well-studied primitives is both educational and safe when done with rigorous testing. What you should never do is invent new primitives or deviate from established best practices.
But using AES-256-GCM, X25519, Ed25519 according to their specifications? That's legitimate learning-by-doing.

---

What's Next
In the next article, we'll move from theory to practice - showing actual code, not just concepts. You'll see exactly how these primitives work and why they're designed the way they are.
The goal isn't just to use these tools blindly. It's to understand them deeply enough that when you see them in production systems, you know what security properties they provide and what assumptions they make.
Because in security engineering, the details matter. And we're about to get into all of them.

---

Next in the series: Cryptographic Foundations: The Building Blocks of Secure Communication