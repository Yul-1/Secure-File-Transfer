#!/usr/bin/env python3
"""
Test File Transfer with Rust Cryptography
Complete integration test of the SFT protocol with Rust crypto module
"""

import sys
import os
import time
import threading
from pathlib import Path
import hashlib

# Import SFT components
try:
    from sft import SecureFileTransferNode
    from python_wrapper import SecureCrypto, SecurityConfig, RUST_MODULE_AVAILABLE
    import crypto_accelerator as crypto_rust

    print(f"✅ Rust module available: {RUST_MODULE_AVAILABLE}")
    print(f"✅ All imports successful\n")
except ImportError as e:
    print(f"❌ Import error: {e}")
    sys.exit(1)

def create_test_file(filepath, size_mb=1):
    """Create a test file with random data"""
    with open(filepath, 'wb') as f:
        # Write random data
        data = crypto_rust.generate_secure_random(size_mb * 1024 * 1024)
        f.write(data)
    return filepath

def calculate_sha256(filepath):
    """Calculate SHA256 of a file"""
    sha256 = hashlib.sha256()
    with open(filepath, 'rb') as f:
        while chunk := f.read(8192):
            sha256.update(chunk)
    return sha256.hexdigest()

def test_file_transfer():
    """Test complete file transfer with Rust cryptography"""
    print("╔════════════════════════════════════════════════════╗")
    print("║   SECURE FILE TRANSFER - RUST CRYPTO TEST         ║")
    print("╚════════════════════════════════════════════════════╝\n")

    # Setup
    test_file = Path("test_transfer_file.bin")
    received_dir = Path("ricevuti")
    received_dir.mkdir(exist_ok=True)

    server_port = 9999
    server_host = "127.0.0.1"

    try:
        # Create test file
        print("📝 Creating test file (1 MB)...")
        create_test_file(test_file, size_mb=1)
        original_hash = calculate_sha256(test_file)
        print(f"   File: {test_file}")
        print(f"   Size: {test_file.stat().st_size / 1024:.2f} KB")
        print(f"   SHA256: {original_hash[:32]}...\n")

        # Create server node (receiver)
        print("🖥️  Starting server node...")
        server = SecureFileTransferNode(
            mode='server',
            host=server_host,
            port=server_port
        )

        # Start server in background thread
        server_thread = threading.Thread(target=server.start, daemon=True)
        server_thread.start()
        time.sleep(1)  # Wait for server to start
        print(f"   ✅ Server listening on {server_host}:{server_port}\n")

        # Create client node (sender)
        print("💻 Creating client node...")
        client = SecureFileTransferNode(
            mode='client',
            host='127.0.0.1',
            port=server_port + 1
        )
        print("   ✅ Client ready\n")

        # Send file
        print("📤 Sending file...")
        print(f"   From: {client.host}:{client.port}")
        print(f"   To: {server_host}:{server_port}")

        result = client.send_file(
            str(test_file),
            server_host,
            server_port
        )

        if result:
            print("   ✅ File sent successfully!\n")
        else:
            print("   ❌ File send failed!\n")
            return False

        # Wait for server to process
        time.sleep(2)

        # Verify received file
        print("📥 Verifying received file...")
        received_file = received_dir / test_file.name

        if not received_file.exists():
            print(f"   ❌ File not found: {received_file}")
            return False

        received_hash = calculate_sha256(received_file)
        print(f"   File: {received_file}")
        print(f"   Size: {received_file.stat().st_size / 1024:.2f} KB")
        print(f"   SHA256: {received_hash[:32]}...\n")

        # Compare hashes
        print("🔍 Comparing file integrity...")
        if original_hash == received_hash:
            print("   ✅ SUCCESS: File integrity verified!")
            print(f"   Original:  {original_hash}")
            print(f"   Received:  {received_hash}")
            print("   Files are identical!\n")
            return True
        else:
            print("   ❌ FAIL: File integrity check failed!")
            print(f"   Original:  {original_hash}")
            print(f"   Received:  {received_hash}")
            return False

    except Exception as e:
        print(f"\n❌ Error during test: {e}")
        import traceback
        traceback.print_exc()
        return False

    finally:
        # Cleanup
        print("\n🧹 Cleanup...")
        if test_file.exists():
            test_file.unlink()
            print(f"   Removed: {test_file}")

        try:
            server.stop()
            client.stop()
            print("   Server and client stopped")
        except:
            pass

def test_crypto_performance():
    """Test cryptographic performance with Rust"""
    print("\n╔════════════════════════════════════════════════════╗")
    print("║         RUST CRYPTO PERFORMANCE TEST               ║")
    print("╚════════════════════════════════════════════════════╝\n")

    # Test data sizes
    sizes = [1024, 10*1024, 100*1024, 1024*1024]  # 1KB, 10KB, 100KB, 1MB

    for size in sizes:
        data = crypto_rust.generate_secure_random(size)
        key = crypto_rust.generate_secure_random(32)
        iv = crypto_rust.generate_secure_random(12)

        # Measure encryption
        start = time.time()
        ciphertext, tag = crypto_rust.aes_gcm_encrypt(data, key, iv, None)
        encrypt_time = (time.time() - start) * 1000  # ms

        # Measure decryption
        start = time.time()
        plaintext = crypto_rust.aes_gcm_decrypt(ciphertext, key, iv, tag, None)
        decrypt_time = (time.time() - start) * 1000  # ms

        throughput_enc = (size / 1024) / (encrypt_time / 1000) if encrypt_time > 0 else 0
        throughput_dec = (size / 1024) / (decrypt_time / 1000) if decrypt_time > 0 else 0

        print(f"Data size: {size/1024:.1f} KB")
        print(f"  Encrypt: {encrypt_time:.3f} ms ({throughput_enc:.1f} KB/s)")
        print(f"  Decrypt: {decrypt_time:.3f} ms ({throughput_dec:.1f} KB/s)")
        print()

def main():
    """Run all tests"""
    print("Starting comprehensive Rust crypto integration tests...\n")

    # Test 1: File Transfer
    transfer_ok = test_file_transfer()

    # Test 2: Performance
    test_crypto_performance()

    # Summary
    print("╔════════════════════════════════════════════════════╗")
    print("║              FINAL TEST SUMMARY                    ║")
    print("╚════════════════════════════════════════════════════╝")

    if transfer_ok:
        print("\n🎉 ALL TESTS PASSED! 🎉")
        print("✅ Rust cryptography module is working perfectly")
        print("✅ File transfer with encryption/decryption successful")
        print("✅ File integrity verified")
        return 0
    else:
        print("\n❌ TESTS FAILED")
        return 1

if __name__ == "__main__":
    sys.exit(main())
