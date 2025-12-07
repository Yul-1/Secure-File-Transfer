#!/usr/bin/env python3
"""
test_crypto_accelerator.py

Suite di test Pytest per il modulo C 'crypto_accelerator'.
Questo test valida la correttezza crittografica, la gestione dei limiti (bounds checking)
e la gestione degli errori di autenticazione del modulo C.

Esecuzione (assumendo che sia in una sottocartella 'tests/'):
$ cd /path/to/project/
$ python3 -m pytest tests/test_crypto_accelerator.py
"""

import pytest
import sys
import os
import hashlib
from pathlib import Path

# --- Configurazione Path ---
# Come richiesto, gestiamo l'esecuzione da una sottocartella.
# Aggiungiamo la directory principale del progetto (la parente di 'tests/') 
# al sys.path per permettere l'import di 'crypto_accelerator.so'.
try:
    project_root = Path(__file__).parent.parent
    sys.path.insert(0, str(project_root))
    import crypto_accelerator as crypto_c
except ImportError:
    print("\n--- ERRORE ---")
    print("Impossibile importare 'crypto_accelerator'.")
    print(f"Assicurati che 'crypto_accelerator.so' (o .dylib/.pyd) sia presente in: {project_root}")
    print("Esegui la compilazione se necessario.")
    print("--------------\n")
    sys.exit(1)
except FileNotFoundError:
    # Caso in cui __file__ non è definito (es. REPL interattivo)
    print("Esegui questo script come file, non in modalità interattiva.")
    sys.exit(1)

# Importiamo i valori MAX/MIN dal wrapper per i test
try:
    from python_wrapper import MAX_BUFFER_SIZE, MIN_BUFFER_SIZE
except ImportError:
    print("Errore nell'importare 'python_wrapper_fixed.py' per le costanti.")
    sys.exit(1)

# --- Costanti di Test ---
AES_KEY_SIZE = 32
AES_NONCE_SIZE = 12
AES_TAG_SIZE = 16

# --- Test Suite ---

# 1. Test Funzionalità Base (Happy Path)
def test_aes_gcm_encrypt_decrypt_safe_happy_path():
    """Verifica il ciclo completo Cifratura -> Decifratura."""
    
    # 1. Dati
    plaintext = b"Questo e' un messaggio segreto da testare" * 10
    key = crypto_c.generate_secure_random(AES_KEY_SIZE)
    iv = crypto_c.generate_secure_random(AES_NONCE_SIZE)
    
    # 2. Cifratura
    try:
        ciphertext, tag = crypto_c.aes_gcm_encrypt(plaintext, key, iv)
    except Exception as e:
        pytest.fail(f"Cifratura (aes_gcm_encrypt) fallita: {e}")
        
    assert ciphertext != plaintext
    assert len(tag) == AES_TAG_SIZE
    
    # 3. Decifratura
    try:
        decrypted = crypto_c.aes_gcm_decrypt(ciphertext, key, iv, tag)
    except Exception as e:
        pytest.fail(f"Decifratura (aes_gcm_decrypt) fallita: {e}")
        
    assert decrypted == plaintext
    print(f"\nTest Happy Path: OK (Len: {len(plaintext)})")

def test_aes_gcm_encrypt_decrypt_safe_empty():
    """Verifica la gestione di plaintext vuoto."""
    
    plaintext = b""
    key = crypto_c.generate_secure_random(AES_KEY_SIZE)
    iv = crypto_c.generate_secure_random(AES_NONCE_SIZE)
    
    try:
        ciphertext, tag = crypto_c.aes_gcm_encrypt(plaintext, key, iv)
        decrypted = crypto_c.aes_gcm_decrypt(ciphertext, key, iv, tag)
    except Exception as e:
        pytest.fail(f"Test 'empty' fallito: {e}")
        
    assert decrypted == plaintext
    assert ciphertext == b""
    assert len(tag) == AES_TAG_SIZE
    print("Test Empty String: OK")

def test_sha256_hash_safe_happy_path():
    """Verifica che l'hash C corrisponda all'hash Python (hashlib)."""
    
    data = b"Dati di test per SHA256" * 5
    
    # Hash C
    try:
        hash_c = crypto_c.sha256_hash(data)
    except Exception as e:
        pytest.fail(f"Hash C (sha256_hash) fallito: {e}")
        
    # Hash Python (Controllo)
    hash_py = hashlib.sha256(data).digest()
    
    assert hash_c == hash_py
    assert len(hash_c) == 32 # 256 bits
    print("Test SHA256: OK")


# 2. Test Gestione Errori e Autenticazione
def test_aes_gcm_decrypt_safe_authentication_fail():
    """
    Verifica che la decifratura fallisca (ValueError) se il TAG è errato.
    Questo è il test di sicurezza più importante per GCM.
    """
    
    plaintext = b"Messaggio autenticato"
    key = crypto_c.generate_secure_random(AES_KEY_SIZE)
    iv = crypto_c.generate_secure_random(AES_NONCE_SIZE)
    
    # 1. Cifratura
    ciphertext, tag = crypto_c.aes_gcm_encrypt(plaintext, key, iv)
    
    # 2. Crea TAG non valido
    invalid_tag = os.urandom(AES_TAG_SIZE)
    assert tag != invalid_tag

    # 3. Verifica fallimento decifratura (TAG ERRATO)
    with pytest.raises(ValueError, match="Decryption failed"):
        crypto_c.aes_gcm_decrypt(ciphertext, key, iv, invalid_tag)
    
    print("Test Auth Fail (Tag): OK")

def test_aes_gcm_decrypt_safe_key_fail():
    """Verifica che la decifratura fallisca (ValueError) se la CHIAVE è errata."""
    
    plaintext = b"Messaggio con chiave specifica"
    key = crypto_c.generate_secure_random(AES_KEY_SIZE)
    iv = crypto_c.generate_secure_random(AES_NONCE_SIZE)
    
    # 1. Cifratura
    ciphertext, tag = crypto_c.aes_gcm_encrypt(plaintext, key, iv)
    
    # 2. Crea Chiave non valida
    invalid_key = os.urandom(AES_KEY_SIZE)
    assert key != invalid_key

    # 3. Verifica fallimento decifratura (CHIAVE ERRATA)
    with pytest.raises(ValueError, match="Decryption failed"):
        # 🟢 FIX (Analisi #4, #19): Esegui solo la chiamata che deve fallire
        crypto_c.aes_gcm_decrypt(ciphertext, invalid_key, iv, tag)
    
    print("Test Auth Fail (Key): OK")

def test_aes_gcm_decrypt_safe_ciphertext_fail():
    """Verifica che la decifratura fallisca (ValueError) se il CIPHERTEXT è corrotto."""
    
    plaintext = b"Messaggio non corrotto"
    key = crypto_c.generate_secure_random(AES_KEY_SIZE)
    iv = crypto_c.generate_secure_random(AES_NONCE_SIZE)
    
    # 1. Cifratura
    ciphertext, tag = crypto_c.aes_gcm_encrypt(plaintext, key, iv)
    
    # 2. Corrompi il ciphertext
    invalid_ciphertext = bytearray(ciphertext)
    invalid_ciphertext[0] = (invalid_ciphertext[0] + 1) % 256 # Flip un bit
    invalid_ciphertext = bytes(invalid_ciphertext)

    # 3. Verifica fallimento decifratura (CIPHERTEXT CORROTTO)
    with pytest.raises(ValueError, match="Decryption failed"):
        crypto_c.aes_gcm_decrypt(invalid_ciphertext, key, iv, tag)
    
    print("Test Auth Fail (Ciphertext): OK")


# 3. Test Tipi e Limiti (Bounds Checking)
def test_aes_gcm_invalid_types():
    """Verifica che le funzioni rifiutino tipi errati (es. str invece di bytes)."""
    
    # Dati validi
    key = b'k' * AES_KEY_SIZE
    iv = b'i' * AES_NONCE_SIZE
    tag = b't' * AES_TAG_SIZE
    data = b'data'
    
    # Test 1: Encrypt
    with pytest.raises(TypeError):
        crypto_c.aes_gcm_encrypt("non-bytes", key, iv) # data
    with pytest.raises(TypeError):
        crypto_c.aes_gcm_encrypt(data, "non-bytes", iv) # key
    with pytest.raises(TypeError):
        crypto_c.aes_gcm_encrypt(data, key, "non-bytes") # iv

    # Test 2: Decrypt
    with pytest.raises(TypeError):
        crypto_c.aes_gcm_decrypt("non-bytes", key, iv, tag) # data
    with pytest.raises(TypeError):
        crypto_c.aes_gcm_decrypt(data, "non-bytes", iv, tag) # key
    with pytest.raises(TypeError):
        crypto_c.aes_gcm_decrypt(data, key, "non-bytes", tag) # iv
    with pytest.raises(TypeError):
        crypto_c.aes_gcm_decrypt(data, key, iv, "non-bytes") # tag

def test_generate_random_bounds():
    """Verifica i limiti (min/max) per generate_secure_random."""
    
    # 1. Test Limite Inferiore
    with pytest.raises(ValueError, match="Invalid buffer size"):
        # 🟢 FIX: MIN_BUFFER_SIZE è 0, quindi -1.
        crypto_c.generate_secure_random(MIN_BUFFER_SIZE - 1) # -1
    
    with pytest.raises(ValueError, match="Invalid buffer size"):
        # 🟢 FIX: Il C-code (corretto) rifiuta 0 per generate_random
        crypto_c.generate_secure_random(0)
    
    # 2. Test Limite Superiore
    with pytest.raises(ValueError, match="Invalid buffer size"):
        crypto_c.generate_secure_random(MAX_BUFFER_SIZE + 1)
        
    # 3. Test Valori Validi
    try:
        # 🟢 FIX: Il minimo valido è 1, non MIN_BUFFER_SIZE (che è 0)
        assert len(crypto_c.generate_secure_random(1)) == 1
        assert len(crypto_c.generate_secure_random(MAX_BUFFER_SIZE)) == MAX_BUFFER_SIZE
    except Exception as e:
        pytest.fail(f"Test limiti (validi) fallito: {e}")

def test_sha256_hash_safe_bounds():
    """Verifica i limiti (min/max) per sha256_hash."""
    
    # 1. Test Limite Inferiore (0 è valido per l'hash)
    try:
        # 🟢 FIX: MIN_BUFFER_SIZE è ora 0, questo test è valido.
        hash_0 = crypto_c.sha256_hash(b"")
        assert len(hash_0) == 32
    except Exception as e:
        pytest.fail(f"Test hash (0 bytes) fallito: {e}")

    # 2. Test Limite Superiore (MAX_BUFFER_SIZE)
    try:
        # (Vedi test_sha256_hash_safe_bounds_max)
        pass
    except Exception as e:
        pytest.fail(f"Test hash (limiti) fallito: {e}")

def test_sha256_hash_safe_bounds_max():
    """Verifica che l'hash fallisca se i dati > MAX_BUFFER_SIZE."""
    # 🟢 FIX (Analisi #20): Implementazione del test bounds superiore
    
    # Crea un buffer leggermente oltre il limite
    # (Python ottimizza b'\x00' * N, quindi non è costoso)
    oversized_data = b'\x00' * (MAX_BUFFER_SIZE + 1)
    
    # Verifica che il modulo C rifiuti input troppo grandi
    with pytest.raises(ValueError, match="Invalid data for hashing size"):
        crypto_c.sha256_hash(oversized_data)
    
    # Verifica che il limite esatto funzioni (edge case)
    max_size_data = b'\x00' * MAX_BUFFER_SIZE
    try:
        result = crypto_c.sha256_hash(max_size_data)
        assert len(result) == 32  # SHA-256 produce sempre 32 bytes
        print(f"✓ SHA256 con MAX_BUFFER_SIZE ({MAX_BUFFER_SIZE} bytes): OK")
    except Exception as e:
        pytest.fail(f"SHA256 dovrebbe accettare MAX_BUFFER_SIZE: {e}") 

# 5. Test compare_digest_safe
def test_compare_digest_safe_identical():
    """Verifica che digest identici ritornino True."""
    a = crypto_c.sha256_hash(b"messaggio 1")
    b = crypto_c.sha256_hash(b"messaggio 1")
    assert crypto_c.compare_digest(a, b) is True

def test_compare_digest_safe_different():
    """Verifica che digest differenti ritornino False."""
    a = crypto_c.sha256_hash(b"messaggio 1")
    b = crypto_c.sha256_hash(b"messaggio 2")
    assert a != b
    assert crypto_c.compare_digest(a, b) is False

def test_compare_digest_safe_different_lengths():
    """Verifica che digest di lunghezze diverse ritornino False."""
    a = b"12345"
    b = b"123456789"
    # 🟢 FIX: Il C-code ora gestisce questo
    assert crypto_c.compare_digest(a, b) is False

def test_compare_digest_safe_types():
    """Verifica che tipi errati (str) falliscano."""
    with pytest.raises(TypeError):
        crypto_c.compare_digest("stringa1", b"bytes2")
    with pytest.raises(TypeError):
        crypto_c.compare_digest(b"bytes1", "stringa2")