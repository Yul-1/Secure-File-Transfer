---

Native Accelerators: When Python Isn't Fast Enough
Building C and Rust Crypto Modules Without Blowing Up on Windows

The pure Python implementation worked. All tests passed. The pipeline handled 500MB files, memory stayed flat, and the handshake was solid.

Then I profiled it.

80-100 MB/s. Consistent, predictable, perfectly adequate for most use cases. But cProfile showed the obvious hotspot: 60% of transfer time was inside encrypt_aes_gcm() and decrypt_aes_gcm(). The rest was I/O, packet framing, and socket operations.

Python's cryptography library already wraps OpenSSL through CFFI, which is fast. But every call crosses the Python/C boundary with serialization overhead. For every 4KB chunk, we paid that price twice: once to encrypt, once to authenticate. Over a 100MB file, that's 25,000 boundary crossings.

The question wasn't "Is this fast enough?" It was "How much faster could we go by keeping the entire encryption loop in native code?"

---

The C Module: OpenSSL Bindings
The first accelerator was pure C using OpenSSL's EVP API. Five functions exposed to Python: aes_gcm_encrypt(), aes_gcm_decrypt(), generate_secure_random(), sha256_hash(), and compare_digest().

The core pattern: Python passes raw bytes, C handles the encryption entirely in native memory, then returns results as Python objects.

c
if (!PyArg_ParseTuple(args, "y#y#y#|y#",
    &plaintext, &plaintext_len, &key, &key_len,
    &iv, &iv_len, &aad, &aad_len)) {
    return NULL;
}

EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv);
// ... encrypt, get tag, return tuple ...
EVP_CIPHER_CTX_free(ctx);

The critical security detail is what happens after encryption: secure_memzero(). Standard memset() gets optimized away by the compiler because the buffer is immediately freed. The sensitive data stays in memory. On Linux we use explicit_bzero(), on Windows SecureZeroMemory(). For older systems, a volatile pointer trick forces the write.

c
secure_memzero(ciphertext_buf, plaintext_len + EVP_MAX_BLOCK_LENGTH);
PyMem_Free(ciphertext_buf);
secure_memzero(tag_buf, 16);
PyMem_Free(tag_buf);

Compilation flags matter as much as the code itself:

bash
gcc -shared -fPIC -O3 -march=native \
    -D_FORTIFY_SOURCE=2 \
    -fstack-protector-strong \
    -Wl,-z,relro,-z,now \
    crypto_accelerator.c -o crypto_accelerator.so -lcrypto

-D_FORTIFY_SOURCE=2 adds bounds checking. -fstack-protector-strong catches stack smashing. -Wl,-z,relro,-z,now makes the GOT read-only. These caught a real bug: I was allocating plaintext_len bytes but writing up to plaintext_len + EVP_MAX_BLOCK_LENGTH. The stack protector caught it immediately.

---

The Memory Corruption Bug
The first version had a subtle use-after-free. After encrypting, I freed the buffer before PyBytes had finished copying the data.

c
// WRONG: Free without zeroing sensitive data
PyObject *result = PyBytes_FromStringAndSize((char*)buf, len);
PyMem_Free(buf);  // Key material still in freed memory

// RIGHT: Zero sensitive data, then free
PyObject *result = PyBytes_FromStringAndSize((char*)buf, len);
secure_memzero(buf, len);
PyMem_Free(buf);

PyBytes_FromStringAndSize() copies the data - it doesn't take ownership. You must still free your buffer. This is documented, but easy to miss. The bug manifested as random corruption on large transfers, only under concurrent load.

---

The Python Wrapper: Fallback Is Non-Negotiable
The wrapper design was critical. If the native module fails to compile or load, the system falls back to pure Python silently.

python
try:
    import crypto_accelerator as crypto_c
    C_MODULE_AVAILABLE = True
except ImportError:
    C_MODULE_AVAILABLE = False

Every crypto function tries the native module first. If it throws any exception, we log it and fall back to the Python implementation. No user-visible errors. No degraded functionality. Just a log entry and slightly slower transfers.

This saved countless hours during cross-platform testing. It also means the project works on any system with Python 3.9+, even without build tools.

---

The Rust Module: Better Windows, Better Safety
The C module worked beautifully on Linux and macOS. On Windows, it was a disaster.

The problem wasn't the code - it was the build environment. OpenSSL on Windows requires vcpkg or a manual Visual Studio build. Python's distutils expects a Unix-like toolchain. Every Windows tester hit a different compilation error.

Rust solved this entirely. The Rust ecosystem handles cross-platform crypto through pure-Rust crates: aes-gcm, sha2, x25519-dalek. No external dependencies. No OpenSSL. cargo build works on every platform.

The PyO3 framework handles Python FFI. The module definition is five lines. Building is one command: maturin build --release. The resulting wheel installs anywhere without a compiler.

But the real win is memory safety:

rust
let mut plaintext = cipher.decrypt(nonce, payload)?;
let result = PyBytes::new(py, &plaintext);
plaintext.zeroize();  // Explicit zeroing via zeroize crate

No manual malloc/free. No use-after-free risks. The ownership system guarantees that sensitive data can't leak through memory management bugs. The Rust compiler caught a bug at build time that would have been a silent vulnerability in C.

---

Benchmarks: C vs Rust vs Python
Testing on a 100MB file, Ryzen 7 5800X with AES-NI:

Pure Python: 95 MB/s (baseline)
C + OpenSSL: 420 MB/s (4.4x faster)
Rust (pure crates): 380 MB/s (4x faster)

The C version edges out Rust because OpenSSL's AES-GCM uses hand-tuned assembly with AES-NI instructions. The pure-Rust crate is portable but slightly slower. Both obliterate the Python baseline.

The real win is CPU usage. Native modules spend less time per byte because they're doing fewer context switches. Python makes 25,000 FFI calls for a 100MB file. The native modules keep the hot loop entirely in compiled code.

---

What I Took Away
Writing native accelerators taught me three things.

First: fallback is non-negotiable. Crypto code that doesn't compile is worse than slow crypto code. The wrapper must handle missing modules gracefully.

Second: memory safety matters more in crypto than anywhere else. A buffer overflow in a web server is bad. A buffer overflow that leaks key material is catastrophic. Rust prevents this by default.

Third: profile before optimizing. I spent two weeks on native code for a 4x speedup. For most users, 95 MB/s was already fast enough. But the exercise forced me to understand every layer's performance characteristics.

Would I do it again? Absolutely. But I'd start with Rust.

---

What's Next
The final article closes the series. We step back from implementation details and look at the project as a whole: what worked, what didn't, what I'd change, and the questions that remain open.

Three months of development, distilled into honest reflection.

---

Next in the series: Lessons Learned: What Three Months of Building Crypto Taught Me
