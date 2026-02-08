#!/usr/bin/env python3
"""
Comprehensive Rust Cryptography Module Testing
Tests all cryptographic functions with real-world scenarios
"""

import sys
import os
from pathlib import Path

# Import Rust module
try:
    import crypto_accelerator as crypto_rust
    print("✅ Rust module imported successfully")
except ImportError as e:
    print(f"❌ Failed to import crypto_accelerator: {e}")
    sys.exit(1)

def test_aes_gcm_encryption():
    """Test AES-256-GCM encryption/decryption"""
    print("\n=== Testing AES-256-GCM ===")

    # Generate random key and IV
    key = crypto_rust.generate_secure_random(32)
    iv = crypto_rust.generate_secure_random(12)

    # Test data
    plaintext = b"This is a secret message that needs to be encrypted!"
    aad = b"Additional authenticated data"

    print(f"Plaintext: {plaintext.decode()}")
    print(f"Key length: {len(key)} bytes")
    print(f"IV length: {len(iv)} bytes")

    # Encrypt
    ciphertext, tag = crypto_rust.aes_gcm_encrypt(plaintext, key, iv, aad)
    print(f"✅ Encryption successful")
    print(f"   Ciphertext length: {len(ciphertext)} bytes")
    print(f"   Tag length: {len(tag)} bytes")

    # Decrypt
    decrypted = crypto_rust.aes_gcm_decrypt(ciphertext, key, iv, tag, aad)
    print(f"✅ Decryption successful")
    print(f"   Decrypted: {decrypted.decode()}")

    # Verify
    assert decrypted == plaintext, "Decryption mismatch!"
    print("✅ Plaintext matches decrypted text")

    # Test authentication failure
    print("\nTesting authentication (wrong tag)...")
    wrong_tag = crypto_rust.generate_secure_random(16)
    try:
        crypto_rust.aes_gcm_decrypt(ciphertext, key, iv, wrong_tag, aad)
        print("❌ Should have failed with wrong tag!")
        return False
    except ValueError as e:
        print(f"✅ Correctly rejected wrong tag: {e}")

    return True

def test_x25519_key_exchange():
    """Test X25519 Diffie-Hellman key exchange"""
    print("\n=== Testing X25519 Key Exchange ===")

    # Alice generates keypair
    alice_secret, alice_public = crypto_rust.x25519_generate_keypair()
    print(f"Alice's public key: {alice_public.hex()[:32]}...")

    # Bob generates keypair
    bob_secret, bob_public = crypto_rust.x25519_generate_keypair()
    print(f"Bob's public key: {bob_public.hex()[:32]}...")

    # Alice computes shared secret
    alice_shared = crypto_rust.x25519_diffie_hellman(alice_secret, bob_public)
    print(f"Alice's shared secret: {alice_shared.hex()[:32]}...")

    # Bob computes shared secret
    bob_shared = crypto_rust.x25519_diffie_hellman(bob_secret, alice_public)
    print(f"Bob's shared secret: {bob_shared.hex()[:32]}...")

    # Verify they match
    assert alice_shared == bob_shared, "Shared secrets don't match!"
    print("✅ Shared secrets match!")

    return True

def test_ed25519_signatures():
    """Test Ed25519 digital signatures"""
    print("\n=== Testing Ed25519 Signatures ===")

    # Generate keypair
    secret_key, public_key = crypto_rust.ed25519_generate_keypair()
    print(f"Public key: {public_key.hex()[:32]}...")

    # Sign message
    message = b"This is an important message that needs to be signed"
    signature = crypto_rust.ed25519_sign(secret_key, message)
    print(f"Message: {message.decode()}")
    print(f"Signature: {signature.hex()[:32]}...")

    # Verify signature
    is_valid = crypto_rust.ed25519_verify(public_key, message, signature)
    assert is_valid, "Signature verification failed!"
    print("✅ Signature verified successfully")

    # Test with modified message
    print("\nTesting with modified message...")
    modified_message = b"This is a MODIFIED message"
    is_valid = crypto_rust.ed25519_verify(public_key, modified_message, signature)
    assert not is_valid, "Should have rejected modified message!"
    print("✅ Correctly rejected modified message")

    return True

def test_sha256_hashing():
    """Test SHA-256 hashing"""
    print("\n=== Testing SHA-256 ===")

    data = b"The quick brown fox jumps over the lazy dog"
    hash_result = crypto_rust.sha256_hash(data)

    print(f"Data: {data.decode()}")
    print(f"SHA-256: {hash_result.hex()}")

    # Known SHA-256 hash for this string
    expected = "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592"
    assert hash_result.hex() == expected, "Hash doesn't match expected value!"
    print("✅ Hash matches expected value")

    # Test determinism
    hash_result2 = crypto_rust.sha256_hash(data)
    assert hash_result == hash_result2, "Hash not deterministic!"
    print("✅ Hash is deterministic")

    return True

def test_hmac_sha256():
    """Test HMAC-SHA256"""
    print("\n=== Testing HMAC-SHA256 ===")

    key = b"secret_key_for_hmac"
    message = b"Message to authenticate with HMAC"

    hmac_result = crypto_rust.hmac_sha256(key, message)
    print(f"Key: {key.decode()}")
    print(f"Message: {message.decode()}")
    print(f"HMAC: {hmac_result.hex()[:32]}...")

    # Test determinism
    hmac_result2 = crypto_rust.hmac_sha256(key, message)
    assert hmac_result == hmac_result2, "HMAC not deterministic!"
    print("✅ HMAC is deterministic")

    # Test different key produces different HMAC
    different_key = b"different_secret_key"
    hmac_different = crypto_rust.hmac_sha256(different_key, message)
    assert hmac_result != hmac_different, "Different keys should produce different HMACs!"
    print("✅ Different keys produce different HMACs")

    return True

def test_pbkdf2():
    """Test PBKDF2 key derivation"""
    print("\n=== Testing PBKDF2 ===")

    password = b"user_password_123"
    salt = crypto_rust.generate_secure_random(16)
    iterations = 600000
    key_length = 32

    print(f"Password: {password.decode()}")
    print(f"Salt: {salt.hex()[:16]}...")
    print(f"Iterations: {iterations}")

    derived_key = crypto_rust.pbkdf2_derive_key(password, salt, iterations, key_length)
    print(f"Derived key: {derived_key.hex()[:32]}...")
    print(f"Key length: {len(derived_key)} bytes")

    # Test determinism
    derived_key2 = crypto_rust.pbkdf2_derive_key(password, salt, iterations, key_length)
    assert derived_key == derived_key2, "PBKDF2 not deterministic!"
    print("✅ PBKDF2 is deterministic")

    # Test different salt produces different key
    different_salt = crypto_rust.generate_secure_random(16)
    derived_different = crypto_rust.pbkdf2_derive_key(password, different_salt, iterations, key_length)
    assert derived_key != derived_different, "Different salts should produce different keys!"
    print("✅ Different salts produce different keys")

    # Test minimum iterations enforcement
    print("\nTesting minimum iterations enforcement...")
    try:
        crypto_rust.pbkdf2_derive_key(password, salt, 1000, key_length)
        print("❌ Should have rejected low iteration count!")
        return False
    except ValueError as e:
        print(f"✅ Correctly rejected low iterations: {e}")

    return True

def test_compare_digest():
    """Test constant-time digest comparison"""
    print("\n=== Testing Constant-Time Comparison ===")

    digest1 = crypto_rust.sha256_hash(b"data1")
    digest2 = crypto_rust.sha256_hash(b"data1")
    digest3 = crypto_rust.sha256_hash(b"data2")

    # Same digests
    assert crypto_rust.compare_digest(digest1, digest2), "Same digests should match!"
    print("✅ Same digests match")

    # Different digests
    assert not crypto_rust.compare_digest(digest1, digest3), "Different digests should not match!"
    print("✅ Different digests don't match")

    # Different lengths
    assert not crypto_rust.compare_digest(digest1, b"short"), "Different lengths should not match!"
    print("✅ Different lengths don't match")

    return True

def test_random_generation():
    """Test secure random number generation"""
    print("\n=== Testing Secure Random Generation ===")

    # Generate random bytes
    random1 = crypto_rust.generate_secure_random(32)
    random2 = crypto_rust.generate_secure_random(32)

    print(f"Random 1: {random1.hex()[:32]}...")
    print(f"Random 2: {random2.hex()[:32]}...")

    # Should be different
    assert random1 != random2, "Random values should be different!"
    print("✅ Random values are unique")

    # Correct length
    assert len(random1) == 32, "Wrong length!"
    print("✅ Correct length")

    return True

def test_input_validation():
    """Test input validation and error handling"""
    print("\n=== Testing Input Validation ===")

    # Test invalid key size for AES
    print("Testing invalid AES key size...")
    try:
        crypto_rust.aes_gcm_encrypt(b"data", b"short", b"123456789012", None)
        print("❌ Should have rejected invalid key size!")
        return False
    except ValueError as e:
        print(f"✅ Correctly rejected: {e}")

    # Test invalid IV size
    print("\nTesting invalid IV size...")
    try:
        key = crypto_rust.generate_secure_random(32)
        crypto_rust.aes_gcm_encrypt(b"data", key, b"short", None)
        print("❌ Should have rejected invalid IV size!")
        return False
    except ValueError as e:
        print(f"✅ Correctly rejected: {e}")

    # Test oversized data
    print("\nTesting oversized data (>10MB)...")
    try:
        oversized = b'\x00' * (10 * 1024 * 1024 + 1)
        crypto_rust.sha256_hash(oversized)
        print("❌ Should have rejected oversized data!")
        return False
    except ValueError as e:
        print(f"✅ Correctly rejected: {e}")

    # Test invalid Ed25519 key size
    print("\nTesting invalid Ed25519 key size...")
    try:
        crypto_rust.ed25519_sign(b"short_key", b"message")
        print("❌ Should have rejected invalid key size!")
        return False
    except ValueError as e:
        print(f"✅ Correctly rejected: {e}")

    return True

def run_all_tests():
    """Run all test suites"""
    print("╔═══════════════════════════════════════════════════╗")
    print("║   COMPREHENSIVE RUST CRYPTO MODULE TESTING       ║")
    print("╚═══════════════════════════════════════════════════╝")

    tests = [
        ("AES-256-GCM Encryption", test_aes_gcm_encryption),
        ("X25519 Key Exchange", test_x25519_key_exchange),
        ("Ed25519 Signatures", test_ed25519_signatures),
        ("SHA-256 Hashing", test_sha256_hashing),
        ("HMAC-SHA256", test_hmac_sha256),
        ("PBKDF2 Key Derivation", test_pbkdf2),
        ("Constant-Time Comparison", test_compare_digest),
        ("Secure Random Generation", test_random_generation),
        ("Input Validation", test_input_validation),
    ]

    results = []
    for name, test_func in tests:
        try:
            success = test_func()
            results.append((name, success))
        except Exception as e:
            print(f"\n❌ Test '{name}' raised exception: {e}")
            import traceback
            traceback.print_exc()
            results.append((name, False))

    # Summary
    print("\n╔═══════════════════════════════════════════════════╗")
    print("║              TEST RESULTS SUMMARY                 ║")
    print("╚═══════════════════════════════════════════════════╝")

    passed = sum(1 for _, success in results if success)
    total = len(results)

    for name, success in results:
        status = "✅ PASS" if success else "❌ FAIL"
        print(f"{status}: {name}")

    print(f"\n{'='*55}")
    print(f"Total: {passed}/{total} tests passed ({passed*100//total}%)")
    print(f"{'='*55}")

    return passed == total

if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
