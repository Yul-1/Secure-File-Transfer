#!/usr/bin/env python3
"""
crypto_wrapper.py - Secure Python wrapper for the C module
Robust validation and error handling
"""

import os
import sys
import hashlib
import hmac
import secrets
import time
import logging
import threading
import subprocess
import platform
import sysconfig
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import padding as sym_padding
from typing import Tuple, Optional, Dict, Any
from pathlib import Path
from dataclasses import dataclass, field
import json
from contextlib import contextmanager
from logging.handlers import RotatingFileHandler

try:
    import crypto_accelerator as crypto_c 
    C_MODULE_AVAILABLE = True
except ImportError as e:
    C_MODULE_AVAILABLE = False

MAX_BUFFER_SIZE = 10 * 1024 * 1024
MIN_BUFFER_SIZE = 1
AES_KEY_SIZE = 32
AES_NONCE_SIZE = 12
AES_TAG_SIZE = 16
DEFAULT_LOGFILE = "crypto_wrapper.log"

logger = logging.getLogger("crypto_wrapper")
logger.setLevel(logging.INFO)
if not logger.handlers:
    handler = RotatingFileHandler(DEFAULT_LOGFILE, maxBytes=5*1024*1024, backupCount=5, encoding='utf-8')
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    console = logging.StreamHandler()
    console.setFormatter(formatter)
    logger.addHandler(console)

if C_MODULE_AVAILABLE:
    logger.info("C acceleration module loaded successfully")

def _clear_memory(data: bytes) -> None:
    """
    Secure memory clearing (best-effort in Python) for sensitive data.
    """
    if data is None:
        return
    try:
        if isinstance(data, bytearray):
            for i in range(len(data)):
                data[i] = 0
        elif isinstance(data, bytes):
            temp = bytearray(data)
            for i in range(len(temp)):
                temp[i] = 0
            del temp
    except Exception:
        pass

@dataclass
class SecurityConfig:
    """Validated security configuration"""
    encryption_algorithm: str = "AES-256-GCM"
    key_derivation: str = "PBKDF2"
    key_rotation_interval: int = field(default=300)
    max_key_cache: int = field(default=3)
    hash_algorithm: str = "SHA256"
    rsa_key_size: int = field(default=4096)
    use_hardware_acceleration: bool = True
    pbkdf2_iterations: int = field(default=600000)

    def __post_init__(self):
        if self.pbkdf2_iterations < 600000:
            logger.warning("PBKDF2 iterations too low, setting to 600000")
            self.pbkdf2_iterations = 600000

class SecureCrypto:
    """
    Secure cryptographic wrapper with robust fallback and safe key caching.
    """
    
    def __init__(self, config: Optional[SecurityConfig] = None):
        """ Initialize wrapper with secure configuration """
        self.config = config or SecurityConfig()
        self.use_c = self.config.use_hardware_acceleration and C_MODULE_AVAILABLE
        self._lock = threading.RLock()
        
        self.stats = {
            'encryptions': 0, 'decryptions': 0, 'hashes': 0,
            'c_module_used': 0, 'python_fallback': 0, 'errors': 0
        }
        
        self._key_cache: Dict[str, bytes] = {} 
        self._key_cache_order: list[str] = [] 
        
        logger.info(f"SecureCrypto initialized (C module: {self.use_c})")
    
    def _validate_size(self, size: int, name: str = "buffer") -> None:
        """Buffer size validation (DoS protection)"""
        if size < MIN_BUFFER_SIZE or size > MAX_BUFFER_SIZE:
            raise ValueError(f"Invalid {name} size: {size}. Must be between {MIN_BUFFER_SIZE} and {MAX_BUFFER_SIZE} bytes.")
    
    @contextmanager
    def _secure_operation(self, operation_name: str):
        """Context manager for secure operations"""
        start_time = time.perf_counter()
        try:
            yield
        except Exception as e:
            with self._lock:
                self.stats['errors'] += 1
            error_message = str(e).split('\n')[0]
            logger.error(f"Error in {operation_name}: {error_message}")
            raise
        finally:
            duration = time.perf_counter() - start_time
            logger.debug(f"{operation_name} took {duration:.6f}s")
    
    def generate_random(self, num_bytes: int) -> bytes:
        """ Generate secure random bytes """
        self._validate_size(num_bytes, "Random bytes")
        
        with self._secure_operation("generate_random"):
            if self.use_c:
                try:
                    with self._lock:
                        self.stats['c_module_used'] += 1
                    return crypto_c.generate_secure_random(num_bytes)
                except Exception as e:
                    logger.debug(f"C module failed for random, falling back: {e}")
            
            with self._lock:
                self.stats['python_fallback'] += 1
            return secrets.token_bytes(num_bytes)
    
    def derive_key(self, password: bytes, salt: bytes, 
                   key_length: int = AES_KEY_SIZE) -> bytes:
        """ Derive key from password using PBKDF2 """
        if len(password) < 8 or len(salt) < 8:
            raise ValueError("Password and salt must be at least 8 bytes.")
            
        with self._secure_operation("derive_key"):
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=key_length,
                salt=salt,
                iterations=self.config.pbkdf2_iterations,
                backend=default_backend()
            )
            
            key = kdf.derive(password)
            
            with self._lock:
                key_id = hashlib.sha256(password + salt).hexdigest()
                
                if len(self._key_cache) >= self.config.max_key_cache:
                    oldest_id = self._key_cache_order.pop(0)
                    old_key = self._key_cache.pop(oldest_id, b'')
                    _clear_memory(old_key)
                    
                if key_id not in self._key_cache:
                    self._key_cache[key_id] = bytes(key)
                    self._key_cache_order.append(key_id)
            
            return key

    def get_key_from_cache(self, password: bytes, salt: bytes) -> Optional[bytes]:
        """Retrieve key from cache for derived ID"""
        key_id = hashlib.sha256(password + salt).hexdigest()
        with self._lock:
            return self._key_cache.get(key_id)
        
    def _cache_put(self, key_id: str, key: bytes):
        with self._lock:
            if len(self._key_cache) >= self.config.max_key_cache:
                oldest_id = self._key_cache_order.pop(0)
                old_key = self._key_cache.pop(oldest_id, b'')
                _clear_memory(old_key)
            if key_id not in self._key_cache:
                self._key_cache[key_id] = bytes(key)
                self._key_cache_order.append(key_id)

    def clear_key_cache(self):
        """
        Completely flush key cache, securely cleaning
        every stored key.
        """
        with self._lock:
            logger.debug(f"Clearing {len(self._key_cache)} keys from cache.")
            for key in self._key_cache.values():
                _clear_memory(key)
            
            self._key_cache.clear()
            self._key_cache_order.clear()

    def encrypt_aes_gcm(self, data: bytes, key: bytes, iv: bytes, aad: bytes = None) -> Tuple[bytes, bytes]:
        """ AES-256-GCM encryption with fallback and AAD support """
        self._validate_size(len(data), "Plaintext")
        
        with self._secure_operation("encrypt"):
            if self.use_c:
                try:
                    with self._lock:
                        self.stats['c_module_used'] += 1
                    # Pass aad to C module (if aad is None, the C module handles it as empty optional)
                    return crypto_c.aes_gcm_encrypt(data, key, iv, aad if aad else b"")
                except Exception as e:
                    logger.debug(f"C module failed for encrypt, falling back: {e}")
                    with self._lock:
                        self.stats['errors'] += 1
            
            with self._lock:
                self.stats['python_fallback'] += 1
            
            if len(key) != AES_KEY_SIZE or len(iv) != AES_NONCE_SIZE:
                raise ValueError("Invalid key or IV size for AES-256-GCM")
                
            cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            if aad:
                encryptor.authenticate_additional_data(aad)
            ciphertext = encryptor.update(data) + encryptor.finalize()
            tag = encryptor.tag
            return ciphertext, tag

    def decrypt_aes_gcm(self, ciphertext: bytes, key: bytes, iv: bytes, tag: bytes, aad: bytes = None) -> bytes:
        """ AES-256-GCM decryption with fallback and AAD support """
        self._validate_size(len(ciphertext), "Ciphertext")

        with self._secure_operation("decrypt"):
            if self.use_c:
                try:
                    with self._lock:
                        self.stats['c_module_used'] += 1
                    return crypto_c.aes_gcm_decrypt(ciphertext, key, iv, tag, aad if aad else b"")
                except Exception as e:
                    logger.debug(f"C module failed for decrypt, falling back: {e}")
                    with self._lock:
                        self.stats['errors'] += 1
            with self._lock:
                self.stats['python_fallback'] += 1
            
            if len(key) != AES_KEY_SIZE or len(iv) != AES_NONCE_SIZE or len(tag) != AES_TAG_SIZE:
                raise ValueError("Invalid key, IV or tag size for AES-256-GCM")
            
            try:
                cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
                decryptor = cipher.decryptor()
                if aad:
                    decryptor.authenticate_additional_data(aad)
                return decryptor.update(ciphertext) + decryptor.finalize()
            except Exception as e:
                raise ValueError(f"Decryption/Authentication failed: {e}")
                
    def compare_digest(self, a: bytes, b: bytes) -> bool:
        """ Constant-time comparison to prevent timing attacks """
        if self.use_c:
            try:
                return crypto_c.compare_digest(a, b)
            except Exception as e:
                logger.debug(f"C module failed for compare_digest, falling back: {e}")
        
        return hmac.compare_digest(a, b)


def compile_c_module():
    """Compile C module with security flags (DoS/stack-smashing protection)"""
    print("Attempting to compile C module...")
    
    c_file_name = "crypto_accelerator.c"
    
    include_path = sysconfig.get_path('include')

    compile_cmd = [
        "gcc", "-shared", "-fPIC", "-O3", 
        f"-I{include_path}",
        "-march=native", 
        "-D_FORTIFY_SOURCE=2", 
        "-fstack-protector-strong",
        "-Wl,-z,relro,-z,now",
        c_file_name, 
        "-o", "crypto_accelerator.so",
        "-lcrypto",
    ]
    
    if platform.system() == "Darwin":
        compile_cmd[0] = "clang"
        compile_cmd[1] = "-dynamiclib"
        compile_cmd[-2] = "crypto_accelerator.dylib"
        compile_cmd = [c for c in compile_cmd if not c.startswith("-Wl,-z")]

    elif platform.system() == "Windows":
        print("Windows compilation requires Visual Studio, skipping compilation.")
        return False
        
    try:
        result = subprocess.run(compile_cmd, capture_output=True, text=True)
        if result.returncode != 0:
            print(f"Compilation failed:\n{result.stderr}")
            return False
        print(f"✓ C module compiled successfully as {compile_cmd[-2]}")
        return True
    except FileNotFoundError:
        print("GCC/Clang not found. Please install build tools.")
        return False

def test_integration():
    """Run integration tests to verify fallback"""
    print("\n--- Running Integration Tests ---")
    crypto = SecureCrypto()
    
    key = crypto.generate_random(AES_KEY_SIZE)
    print(f"Random key generated (len: {len(key)}) using {'C' if crypto.stats['c_module_used'] > 0 else 'Python'}")
    
    plaintext = b"This is a secret message" * 10
    iv = crypto.generate_random(AES_NONCE_SIZE)
    aad = b"header_data"
    
    try:
        ciphertext, tag = crypto.encrypt_aes_gcm(plaintext, key, iv, aad=aad)
        decrypted = crypto.decrypt_aes_gcm(ciphertext, key, iv, tag, aad=aad)
        assert plaintext == decrypted
        print("Encryption/Decryption with AAD successful.")
    except Exception as e:
        print(f"Encryption/Decryption failed: {e}")
        return
        
    try:
        crypto.decrypt_aes_gcm(ciphertext, key, iv, b'\x00' * AES_TAG_SIZE, aad=aad)
        assert False, "Authentication tag check failed to raise error"
    except ValueError as e:
        print(f"Authentication failure caught: {e}")

    try:
        crypto.decrypt_aes_gcm(ciphertext, key, iv, tag, aad=b"corrupted_header")
        assert False, "AAD check failed to raise error"
    except ValueError as e:
        print(f"AAD mismatch failure caught: {e}")
    
    print("--- Tests Complete ---")

def benchmark_comparison():
    """Run simple C vs Python benchmark"""
    print("\n--- Running Benchmark ---")
    crypto = SecureCrypto()
    data_size = 10 * 1024 * 1024
    data = os.urandom(data_size)
    key = os.urandom(AES_KEY_SIZE)
    iv = os.urandom(AES_NONCE_SIZE)
    
    iterations = 5

    def run_op(func, label):
        times = []
        for _ in range(iterations):
            start = time.perf_counter()
            func()
            times.append(time.perf_counter() - start)
        avg_time = sum(times) / iterations
        print(f"{label}: {avg_time:.4f}s (Avg over {iterations} runs)")

    if crypto.use_c:
        try:
            print("C Module Encryption:")
            run_op(lambda: crypto_c.aes_gcm_encrypt(data, key, iv, b""), "C Encrypt")
        except Exception:
            print("C Encrypt failed, skipping.")

    print("Python Fallback Encryption:")
    run_op(lambda: crypto.encrypt_aes_gcm(data, key, iv), "Python Encrypt")
    
    print("--- Benchmark Complete ---")


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='Secure Crypto Wrapper')
    parser.add_argument('--test', action='store_true', help='Run integration tests')
    parser.add_argument('--benchmark', action='store_true', help='Run benchmark')
    parser.add_argument('--compile', action='store_true', help='Compile C module')
    
    args = parser.parse_args()
    
    if args.compile:
        compile_c_module()
    
    if args.test:
        test_integration()
    
    if args.benchmark:
        benchmark_comparison()

    if not args.compile and not args.test and not args.benchmark:
        logger.info("Secure Crypto Wrapper loaded. Run with --compile, --test, or --benchmark.")