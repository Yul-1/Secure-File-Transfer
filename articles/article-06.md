# Lessons Learned: What Three Months of Building Crypto Taught Me

## The Question That Started Everything

It's February 2026. Three months after that first commit on October 28th, the Secure File Transfer project has evolved through 100+ commits, three implementations, seventeen security fixes, and more debugging sessions at 2 AM than I care to admit.

The original question was deceptively simple: *What does "secure" really mean?*

I thought I'd find the answer in algorithms and key sizes. In choosing AES-256 over AES-128, or X25519 over RSA. I thought security was about picking the right cryptographic primitives from a menu.

I was spectacularly wrong.

**The answer is that security means trade-offs.** Constant, deliberate trade-offs between performance and safety, usability and paranoia, complexity and maintainability. Every decision sacrifices something to gain something else.

This is the final article in the series. Not a tutorial. Just an honest reflection on what worked, what didn't, and what I learned.

---

## What Actually Worked

**The layered architecture saved my sanity.** Splitting the system into protocol logic (Python), crypto wrapper (Python with fallback), and native core (C/Rust) meant I could iterate on protocol design quickly without fighting segfaults. When I needed performance, I dropped to native code. When something broke, Python told me exactly where.

**Automatic fallback was non-negotiable.** When native modules fail to compile, transfers continue in pure Python. No exceptions. No degraded state. Just a log entry saying "using pure Python implementation" and slightly slower transfers. This meant the project worked everywhere from day one, even when native builds were broken.

**Migrating from RSA to ECDH eliminated a real attack.** Version 1.0 used RSA-4096 for key exchange, which was vulnerable to CPU exhaustion DoS. Switching to X25519 made the computational cost symmetric between client and server, closing that vector entirely.

**AAD protected against attacks I didn't understand at first.** Without Additional Authenticated Data on packet headers, an attacker could modify sequence numbers while leaving encrypted payloads intact. AES-GCM would decrypt successfully because the ciphertext was untouched. With AAD, headers are cryptographically bound to ciphertext—change one byte and decryption fails.

---

## What Didn't Work

**Unbounded memory growth nearly became a DoS vector.** Early versions cached derived keys indefinitely. Under load with hundreds of clients, memory usage grew without bound. The penetration test flagged this immediately. The fix was obvious in retrospect: an LRU cache capped at three entries with expiration timeouts.

**Rate-limiting everything destroyed performance.** I initially throttled handshakes, authentication messages, and data chunks. A 1GB file took over a minute instead of 10 seconds. The better approach: rate-limit handshakes aggressively to prevent DoS, but let authenticated sessions run at full speed.

**Concurrent nonce generation was subtly dangerous.** Each thread generated nonces independently without coordination. Under specific timing, two threads could theoretically produce the same nonce for the same session key—catastrophic for GCM mode. Per-thread CSPRNG seeding fixed it, but it taught me how concurrency multiplies cryptographic risks.

---

## The Bug That Haunted Me

I found and fixed seventeen security bugs. But one stands out: **the symlink attack vulnerability.**

A malicious server could create a symlink pointing to `/etc/passwd`, then serve it when the client requested a file download. The client thought it was receiving `harmless_data.txt` but was actually exfiltrating sensitive system files.

The fix combined `O_NOFOLLOW` flags and strict filename sanitization that rejects path traversal patterns. This closed the entire vulnerability class.

**What made this bug memorable was how completely it blindsided me.** I was obsessed with cryptographic correctness—key exchange, nonce uniqueness, authentication tags. The idea that an attacker would exploit the *filesystem* rather than the *crypto* never occurred to me.

This taught me something crucial: **cryptographic strength is meaningless if implementation bugs provide easier attack paths.** Security isn't just about the math. It's about every line of code between the user and the crypto.

---

## What I'd Do Differently

**Skip C entirely and go straight to Rust.** As I covered in the previous article, the Rust compiler catches entire classes of memory bugs at build time. The 5-10% throughput advantage of OpenSSL's hand-tuned assembly doesn't justify the security risks of manual memory management in cryptographic code.

**Invest in fuzzing earlier.** I never fuzzed the protocol parser. AFL or libFuzzer could have found input-handling bugs that slipped through manual test cases. Fuzzers try millions of malformed inputs—they're tireless and creative in ways humans aren't.

**Add formal verification.** The handshake has five states. I tested transitions manually, but tools like TLA+ could have *proved* correctness mathematically. The discipline of specifying the system formally enough to verify it would have clarified design inconsistencies.

---

## The Real Lesson: Security Is Discipline

The most valuable thing I learned wasn't about cryptography. It was about discipline.

**Security is not a feature you add at the end.** It's a mindset from the first line of code. It's asking "what if this input is malicious?" before writing the parser. It's testing failure paths as rigorously as happy paths.

I started thinking security was 90% about choosing algorithms. AES-256 instead of AES-128. X25519 instead of RSA-2048. 

I ended understanding that **the encryption algorithm is maybe 5% of the solution. The engineering discipline is the other 95%.**

Threat modeling. Input validation. Memory management. Error handling without information leakage. Logging that doesn't expose secrets. Rate limiting. Resource bounds. State machine correctness.

These don't appear in cryptography textbooks. But they're where real systems succeed or fail.

---

## Final Thoughts: Should You Build Your Own?

Would I recommend building your own cryptographic protocol from scratch? **No.**

Would I recommend doing it as a learning exercise, with the explicit understanding that it won't see production without extensive external audit? **Absolutely.**

This project taught me more about security engineering than any course or certification. Not because the knowledge is unavailable—it's all documented in RFCs and papers. But implementation forces you to confront every detail you glossed over in theory.

Reading about nonce reuse in GCM teaches you it's bad. Debugging why your file transfer corrupts when two threads use the same nonce teaches you *why* it's catastrophic. The difference between knowing and understanding comes from making the mistake and fixing it.

**If you want to learn cryptography deeply: build something real.** Pick a protocol. Implement it. Test it. Break it. Fix it.

But never deploy it to production without expert review.

Use battle-tested tools—OpenSSH, TLS, Signal Protocol—for anything that actually matters. Reserve your own implementations for learning and understanding why those tools make the choices they do.

---

The Secure File Transfer project started with a question: *What does secure really mean?*

The answer isn't a formula or algorithm. It's a process. A disciplined, paranoid, adversarial process of building systems that fail gracefully, validate rigorously, and assume every byte is hostile until proven otherwise.

It's understanding that security is built from a thousand small decisions, and getting one wrong can unravel everything.

That's what I learned. And despite the late nights, mysterious segfaults, and seventeen security bugs—I'd do it all over again.

Because now I actually understand what "secure" means.

---

*The complete code is available at [github.com/Yul-1/Secure-File-Transfer](https://github.com/Yul-1/Secure-File-Transfer)*