#!/usr/bin/env python3
"""
Suite di Test Categoria 10 (Concorrenza) e 7 (Thread-Safety C)
Team: _team controllo
(Versione 1.2: Corretto nome fixture 'persistent_server')
"""

import pytest
import threading
import time
import socket
import logging
import os
import hashlib
import sys
from pathlib import Path
from typing import Tuple, Generator, List, Any

# --- Configurazione Path ---
try:
    project_root = Path(__file__).parent.parent
    sys.path.insert(0, str(project_root))
    
    from sft import (
        SecureFileTransferNode,
        OUTPUT_DIR,
        MAX_GLOBAL_CONNECTIONS
    )
    from python_wrapper import (
        SecureCrypto,
        SecurityConfig,
        RUST_MODULE_AVAILABLE,
        AES_KEY_SIZE,
        AES_NONCE_SIZE
    )
    if RUST_MODULE_AVAILABLE:
         import crypto_accelerator as crypto_c

except ImportError as e:
    print(f"\n--- ERRORE DI IMPORT ---")
    print(f"Errore: {e}")
    print(f"Assicurati che 'secure_file_transfer_fixed.py', 'python_wrapper_fixed.py' e 'crypto_accelerator.so' siano in: {project_root}")
    sys.exit(1)


# Utility per calcolare l'hash
def sha256_file(file_path: Path) -> str:
    h = hashlib.sha256()
    with file_path.open('rb') as f:
        while chunk := f.read(8192):
            h.update(chunk)
    return h.hexdigest()

CONCURRENT_THREADS = 30 

# --- Fixtures ---
# Rimosse. Si affida a conftest.py

@pytest.fixture(scope="module")
def crypto_wrapper() -> SecureCrypto:
    """Fixture per un'istanza del wrapper C (se disponibile)."""
    if not RUST_MODULE_AVAILABLE:
        pytest.skip("Modulo C non disponibile, salto test thread-safety C.")
        
    config = SecurityConfig(use_hardware_acceleration=True)
    crypto = SecureCrypto(config)
    assert crypto.use_c is True
    return crypto


# --- Test Categoria 7 (Thread-Safety C) ---

def crypto_worker_c_module(crypto: SecureCrypto, barrier: threading.Barrier, results: list):
    """
    Worker per il test di thread-safety del C.
    """
    try:
        key = os.urandom(AES_KEY_SIZE)
        iv = os.urandom(AES_NONCE_SIZE)
        plaintext = os.urandom(1024)
        
        barrier.wait()
        
        for _ in range(10):
            ciphertext, tag = crypto.encrypt_aes_gcm(plaintext, key, iv)
            decrypted = crypto.decrypt_aes_gcm(ciphertext, key, iv, tag)
            assert decrypted == plaintext
            
        results.append(None) # Successo
    except Exception as e:
        results.append(e) # Fallimento

def test_p2_c_module_thread_safety(crypto_wrapper: SecureCrypto):
    """
    (CAT 7) Verifica che il modulo C sia thread-safe.
    (FIX 1.1: Corretto .get_stats() -> .stats)
    """
    print(f"\n--- test_p2_c_module_thread_safety ({CONCURRENT_THREADS} threads) ---")
    
    crypto_wrapper.stats = {'c_module_used': 0, 'python_fallback': 0, 'errors': 0}
    
    threads: List[threading.Thread] = []
    results: List[Any] = []
    barrier = threading.Barrier(CONCURRENT_THREADS)
    
    for i in range(CONCURRENT_THREADS):
        t = threading.Thread(
            target=crypto_worker_c_module,
            args=(crypto_wrapper, barrier, results),
            name=f"CryptoWorker-{i}"
        )
        threads.append(t)
        t.start()
        
    print("Avvio thread... Attesa completamento...")
    
    for t in threads:
        t.join()
        
    print("Tutti i thread C completati.")
    
    exceptions = [r for r in results if isinstance(r, Exception)]
    assert len(exceptions) == 0, f"Errori di thread-safety C rilevati: {exceptions}"
    assert len(results) == CONCURRENT_THREADS, "Numero errato di risultati"
    
    stats = crypto_wrapper.stats
    expected_calls = 10 * 2 * CONCURRENT_THREADS
    assert stats['c_module_used'] >= expected_calls
    
    print("Test P2.7 (C-Module Thread-Safety) completato: Nessun crash o errore.")


# --- Test Categoria 10 (Concorrenza Server) ---

def client_upload_worker(server_port: int, file_to_upload: Path, file_hash: str, results: list):
    """
    Worker per lo stress test del server.
    """
    client = None
    try:
        client = SecureFileTransferNode(mode='client')
        client.connect_to_server('127.0.0.1', server_port)
        client.send_file(str(file_to_upload))
        results.append({'file': file_to_upload.name, 'hash': file_hash})
    except Exception as e:
        results.append(e)
    finally:
        if client:
            client.shutdown()

def test_p2_server_stress_test_concurrent_uploads(
    persistent_server: SecureFileTransferNode, # (FIX 2.0) Usa 'persistent_server'
    server_output_dir: Path, # (FIX 2.0) Inietta fixture
    tmp_path: Path, 
    monkeypatch: pytest.MonkeyPatch
):
    """
    (CAT 10) Stress test: Simula N client che caricano N file unici
    simultaneamente.
    (FIX 2.0: Corretto nome fixture e iniezione dir)
    """
    print(f"\n--- test_p2_server_stress_test_concurrent_uploads ({CONCURRENT_THREADS} threads) ---")
    
    monkeypatch.setattr(persistent_server.connection_limiter, "max_requests", 500)
    
    for f in server_output_dir.glob('*'):
        if f.is_file():
            f.unlink()

    client_files = [] 
    for i in range(CONCURRENT_THREADS):
        file_path = tmp_path / f"stress_file_{i:03d}.dat"
        file_data = os.urandom(1024 * 10) # 10KB
        file_path.write_bytes(file_data)
        file_hash = sha256_file(file_path)
        client_files.append((file_path, file_hash))
        
    threads: List[threading.Thread] = []
    results: List[Any] = []
    server_port = persistent_server.port
    
    print(f"Avvio {CONCURRENT_THREADS} thread client...")
    
    for file_path, file_hash in client_files:
        t = threading.Thread(
            target=client_upload_worker,
            args=(server_port, file_path, file_hash, results)
        )
        threads.append(t)
        t.start()
        time.sleep(0.01) 
        
    print("Attesa completamento upload...")
    for t in threads:
        t.join()
        
    print("Tutti i thread client completati.")
    
    exceptions = [r for r in results if isinstance(r, Exception)]
    
    assert len(exceptions) == 0, f"Errori durante l'upload concorrente: {exceptions}"
    assert len(results) == CONCURRENT_THREADS, "Numero errato di risultati client"
    
    server_files = list(server_output_dir.glob('stress_file_*.dat'))
    assert len(server_files) == CONCURRENT_THREADS, \
        f"Il server ha ricevuto {len(server_files)} file, attesi {CONCURRENT_THREADS}"
        
    print("Verifica hash sul server...")
    
    expected_hashes = {r['file']: r['hash'] for r in results}
    
    for server_file_path in server_files:
        server_hash = sha256_file(server_file_path)
        assert server_file_path.name in expected_hashes, \
            f"File inatteso sul server: {server_file_path.name}"
            
        expected = expected_hashes[server_file_path.name]
        assert server_hash == expected, \
            f"HASH MISMATCH per {server_file_path.name}. Atteso: {expected[:10]}..., Ricevuto: {server_hash[:10]}..."

    print("Test P2.10 (Stress Test Server) completato: Tutti i file sono stati ricevuti correttamente.")

    # Pulizia
    for f in server_files:
        f.unlink()