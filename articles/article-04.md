---

The Encryption Pipeline: From File to Wire and Back Again
How to Move 500MB Without Blowing Up Your Memory

The handshake worked. The channel was secure. Session keys derived correctly. Perfect.

Then I tried to send an actual file.

The first test was a 500MB video. The client froze for about 45 seconds, then the server's memory usage spiked to 2GB and the entire connection timed out. Zero bytes transferred.

The problem was obvious in retrospect: I was reading the entire file into memory, encrypting it as one giant blob, then trying to push it through a socket with a 30-second timeout. This doesn't scale. At all.

The solution is chunking - breaking files into small pieces, encrypting each independently, and streaming them across the wire. But chunking introduces its own complexity: how do you reassemble chunks in order? What happens when a chunk gets corrupted? How do you resume an interrupted transfer?

This is the story of building that pipeline, complete with the bugs that taught me the most.

---

Why Chunking Is Non-Negotiable
Without chunking, a 5GB file means 5GB in RAM plus ciphertext plus OS buffers. You'll OOM before the transfer completes. TCP sockets have timeouts - block too long and the peer thinks you're dead. Users get zero progress feedback until the entire operation succeeds or fails. And if the connection drops at 99%, you start over from zero.

SFT uses a 4KB chunk size (BUFFER_SIZE = 4096). Memory usage stays constant regardless of file size. Each chunk encrypts and transmits in milliseconds. Progress callbacks fire after every chunk. Resume points happen at chunk boundaries.

The trade-off is a robust packet format and careful state management.

---

The Packet Format
Every chunk that crosses the wire follows a strict 65-byte header:

python
HEADER_FORMAT = '!4sI B Q I 16s 12s 16s'
# Magic (4B) + Version (4B) + PayloadType (1B) + Offset (8B)
# + PayloadLen (4B) + KeyID (16B) + Nonce (12B) + Tag (16B)

After the header comes the ciphertext. Two payload types exist: JSON (0x01) for control messages like file_header and file_complete, and DATA (0x02) for actual file chunks.

The Offset field is critical for resume. If a transfer dies at byte 5,242,880, the receiver tells the sender "start from here" and the sender seeks directly to that position.

The most important design choice: every header field becomes part of the AAD (Additional Authenticated Data) for that chunk's encryption. Before encrypting, we pack all metadata into a 57-byte AAD and pass it to AES-GCM.

This means an attacker can't take chunk 500 and replay it as chunk 100. The offset is authenticated - changing it invalidates the GCM tag. Same protection applies to nonces, version numbers, and payload lengths. The header is readable but tamper-proof.

---

The Transfer State Machine
The sender and receiver follow a strict exchange:

1. Sender computes SHA-256 hash of the entire file
2. Sender sends file_header (filename, size, hash)
3. Receiver checks for existing partial file
4. Receiver responds with file_resume_ack including the byte offset to start from
5. Sender seeks to that offset and begins streaming encrypted chunks
6. Each chunk gets a fresh nonce, encrypted with AES-GCM, packed with the 65-byte header
7. Sender sends file_complete when done
8. Receiver verifies the full file's SHA-256 against the hash from step 2
9. Receiver responds with file_ack (success or hash mismatch error)

The buffer reuse pattern keeps memory flat:

python
chunk_ba = bytearray(BUFFER_SIZE)
chunk_view = memoryview(chunk_ba)
while current_offset < total_size:
    read_len = f.readinto(chunk_ba)
    chunk_data = bytes(chunk_view[:read_len])
    data_packet = protocol._create_data_packet(chunk_data, current_offset)
    sock.sendall(data_packet)

One bytearray, one memoryview, reused for every chunk. No allocation storms. No GC pressure. For multi-gigabyte files, this matters.

The end-to-end SHA-256 verification is a safety net beyond per-chunk GCM authentication. It catches bugs in reassembly logic, disk write errors, and any corruption outside the cryptographic channel. If the hash fails, the receiver deletes the file immediately. No zombie files.

---

Bug #1: Sequence Number Validation (December 8th)
The handshake completed perfectly. File transfers started. Then every single transfer immediately failed with "Sequence number validation failed."

The error appeared on the very first DATA packet. The sender was incrementing properly (0, 1, 2...), and the receiver was tracking the expected value. The logging showed correct sequence numbers on both sides. So why was validation failing?

After adding verbose debug logging to the actual comparison, I found it:

python
# Initialization
self.peer_sequence_number = 0

# Validation
def _validate_sequence_number(self, seq: int) -> bool:
    if seq <= self.peer_sequence_number:  # 0 <= 0 is True!
        return False  # Rejected as duplicate
    self.peer_sequence_number = seq
    return True

The receiver initialized peer_sequence_number to 0. When the first packet arrived with seq=0, the check evaluated 0 <= 0, which is true, so it rejected the packet as a duplicate.

Classic off-by-one with a twist. The validation logic was correct for ongoing transfers - sequence numbers must strictly increase. But the initialization was wrong.

The fix:
python
self.peer_sequence_number = -1  # Sentinel: no packets received yet

Now the first packet check becomes 0 <= -1, which is false - accepted. A one-character change that took 18 hours to find because the logging only showed "validation failed" without the actual comparison values.

---

Bug #2: Source File Truncation (December 6th)
This was the most dangerous bug in the entire project. It caused silent data loss.

Scenario: client and server run from the same directory. User uploads test.txt which already exists on the server with the same size.

What happened:
1. Client opens test.txt for reading
2. Server receives file_header, sees file exists with matching size
3. Server opens test.txt in 'wb' mode (write, truncate)
4. File is now 0 bytes
5. Client tries to read next chunk
6. Client detects "File size changed: was 1024, now 0"
7. Transfer fails. Source file destroyed.

The server's open(path, 'wb') truncated the file while the client was still reading from it. Both processes had handles to the same file.

The fix uses temporary files:
python
if safe_path.exists() and safe_path.stat().st_size >= total_size:
    temp_fd, temp_path = tempfile.mkstemp(
        dir=OUTPUT_DIR, prefix=f".tmp_{filename}_", suffix=".part"
    )
    os.close(temp_fd)
    actual_write_path = Path(temp_path)

Now the server writes to a .part temp file. After hash verification succeeds, it atomically renames to the final destination. If the transfer fails, the temp file is deleted and the original stays untouched.

This bug survived testing because I always used different directories for client and server. The shared-directory case only appeared in real usage. Another reminder: your test setup is never realistic enough.

---

What Matters Here
The encryption pipeline looks simple in architecture diagrams: "chunk, encrypt, send." Three boxes and two arrows.

The implementation is 800 lines. The crypto part - AES-GCM with AAD - is maybe 50 of those lines. The other 750 handle state management, error recovery, buffer reuse, resume logic, and the 47 ways a transfer can fail.

This is normal. Production systems spend 95% of their code on error handling and 5% on the happy path. The happy path is easy. The failure modes are where the work lives.

The pipeline runs at about 80-100 MB/s on my test hardware, limited mostly by Python's interpreter overhead. Fast enough for now - but modern SSDs push 2-3 GB/s. We're leaving performance on the table.

---

What's Next
The protocol works. Files transfer correctly. Encryption is sound. But pure Python has a ceiling around 100 MB/s for cryptographic operations, even with careful buffer management.

In the next article, we drop down to native code. The cryptographic hot path moves to C (via OpenSSL) and Rust, while Python keeps orchestrating the protocol. We'll explore FFI patterns, memory safety between languages, and whether the performance gain justifies the complexity.

Spoiler: it does. But not for the reasons I expected.

---

Next in the series: Native Accelerators - When Python Isn't Fast Enough
