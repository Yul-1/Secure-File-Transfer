#!/usr/bin/env python3
"""
Test to verify the fix for the critical bug where source files were being
deleted when client and server shared the same directory.

Root Cause: When server received file_header with filename matching an existing
file of the same size, it would open the file in 'wb' mode (truncating to 0 bytes)
BEFORE the client finished reading it, causing the upload to fail with "File size
changed: was X, now 0".

Fix: Use temporary file for writes when file exists with same/larger size, then
atomically rename after successful transfer and hash verification.
"""

import os
import sys
import time
import hashlib
import subprocess
import signal
from pathlib import Path
import threading

def create_test_file(filepath, size_bytes=10240):
    """Create a test file with random content and return its hash"""
    with open(filepath, 'wb') as f:
        content = os.urandom(size_bytes)
        f.write(content)

    file_hash = hashlib.sha256(content).hexdigest()
    print(f"[TEST] Created {filepath} ({size_bytes} bytes, hash: {file_hash[:16]}...)")
    return file_hash

def verify_file(filepath, expected_hash=None):
    """Verify file exists and optionally check its hash"""
    if not os.path.exists(filepath):
        print(f"[FAIL] File missing: {filepath}")
        return False

    size = os.path.getsize(filepath)
    print(f"[OK] File exists: {filepath} ({size} bytes)")

    if expected_hash:
        with open(filepath, 'rb') as f:
            actual_hash = hashlib.sha256(f.read()).hexdigest()
        if actual_hash == expected_hash:
            print(f"[OK] Hash matches: {actual_hash[:16]}...")
            return True
        else:
            print(f"[FAIL] Hash mismatch!")
            print(f"  Expected: {expected_hash[:16]}...")
            print(f"  Actual:   {actual_hash[:16]}...")
            return False

    return True

def main():
    print("=" * 80)
    print("SOURCE FILE PRESERVATION TEST")
    print("Testing fix for bug where files were deleted during upload")
    print("=" * 80)

    test_dir = Path("ricevuti")
    test_dir.mkdir(exist_ok=True)

    test_file = test_dir / "source_preservation_test.bin"

    # Clean up
    if test_file.exists():
        test_file.unlink()

    # Create test file
    print("\n[STEP 1] Creating source file in ricevuti/")
    original_hash = create_test_file(test_file, size_bytes=10240)

    # Verify it exists
    if not verify_file(test_file, original_hash):
        print("\n[ERROR] Failed to create test file")
        return 1

    original_stat = test_file.stat()
    original_inode = original_stat.st_ino
    original_size = original_stat.st_size

    print(f"\n[INFO] Original file:")
    print(f"  Path: {test_file}")
    print(f"  Inode: {original_inode}")
    print(f"  Size: {original_size}")
    print(f"  Hash: {original_hash[:16]}...")

    # Start server in background
    print("\n[STEP 2] Starting server...")
    server_proc = subprocess.Popen(
        ["python3", "sft.py", "--mode", "server", "--port", "7777"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    time.sleep(2)  # Wait for server to start

    if server_proc.poll() is not None:
        print("[ERROR] Server failed to start")
        stdout, stderr = server_proc.communicate()
        print(f"STDOUT: {stdout}")
        print(f"STDERR: {stderr}")
        return 1

    print("[OK] Server started (PID: {})".format(server_proc.pid))

    try:
        # Upload file to localhost (same directory scenario)
        print("\n[STEP 3] Uploading file to server on same machine...")
        print(f"  Client will upload: {test_file}")
        print(f"  Server will save to: ricevuti/{test_file.name}")
        print(f"  WARNING: This is the bug scenario (shared directory)!")

        client_proc = subprocess.Popen(
            ["python3", "sft.py", "--mode", "client", "--connect", "127.0.0.1:7777",
             "--file", str(test_file)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        stdout, stderr = client_proc.communicate(timeout=15)

        print("\n[CLIENT OUTPUT]")
        print(stdout)
        if stderr:
            print("\n[CLIENT STDERR]")
            print(stderr)

        # Check if client succeeded
        if client_proc.returncode != 0:
            print(f"\n[FAIL] Client exited with code {client_proc.returncode}")
            return 1

        print("\n[STEP 4] Verifying source file integrity...")

        # The critical check: source file must still exist and be intact
        if not test_file.exists():
            print(f"\n[CRITICAL FAILURE] Source file was DELETED!")
            print(f"  Missing file: {test_file}")
            print(f"\n  This confirms the bug is NOT fixed!")
            return 1

        current_stat = test_file.stat()
        current_size = current_stat.st_size
        current_inode = current_stat.st_ino

        if current_size == 0:
            print(f"\n[CRITICAL FAILURE] Source file was TRUNCATED to 0 bytes!")
            print(f"  File: {test_file}")
            print(f"  Original size: {original_size}")
            print(f"  Current size: {current_size}")
            print(f"\n  This confirms the bug is NOT fixed!")
            return 1

        if current_size != original_size:
            print(f"\n[FAILURE] Source file size changed!")
            print(f"  Original: {original_size}")
            print(f"  Current: {current_size}")
            return 1

        # Verify hash
        with open(test_file, 'rb') as f:
            current_hash = hashlib.sha256(f.read()).hexdigest()

        if current_hash != original_hash:
            print(f"\n[FAILURE] Source file content was modified!")
            print(f"  Original hash: {original_hash[:16]}...")
            print(f"  Current hash:  {current_hash[:16]}...")
            return 1

        print(f"\n[SUCCESS] Source file preserved!")
        print(f"  File: {test_file}")
        print(f"  Size: {current_size} (unchanged)")
        print(f"  Inode: {current_inode} (unchanged: {current_inode == original_inode})")
        print(f"  Hash: {current_hash[:16]}... (matches)")

        print("\n" + "=" * 80)
        print("TEST PASSED: Source file preservation fix is working correctly!")
        print("=" * 80)

        return 0

    except subprocess.TimeoutExpired:
        print("\n[ERROR] Client timeout (15s)")
        client_proc.kill()
        return 1
    except Exception as e:
        print(f"\n[ERROR] Test failed with exception: {e}")
        import traceback
        traceback.print_exc()
        return 1
    finally:
        # Clean up
        print("\n[CLEANUP] Stopping server...")
        server_proc.terminate()
        try:
            server_proc.wait(timeout=5)
            print("[OK] Server stopped")
        except subprocess.TimeoutExpired:
            print("[WARN] Server did not stop gracefully, killing...")
            server_proc.kill()
            server_proc.wait()

        # Remove test file
        if test_file.exists():
            test_file.unlink()
            print(f"[OK] Removed test file: {test_file}")

if __name__ == '__main__':
    sys.exit(main())
