#!/usr/bin/env python3
"""
test_python_wrapper.py

Suite di test Pytest per il wrapper 'python-wrapper-fixed.py'.
Questo test valida la logica di fallback (C vs Python), la gestione degli errori C
e la logica di caching sicura (eviction e clear memory).

(FIX: Corretta asserzione in test_key_cache_derivation_and_retrieval
 per aspettarsi 'bytes' invece di 'bytearray')
"""

import pytest
import sys
import os
import hashlib
from pathlib import Path
from unittest.mock import patch, MagicMock, ANY

# --- Configurazione Path ---
# Aggiungiamo la directory principale del progetto
try:
    project_root = Path(__file__).parent.parent
    sys.path.insert(0, str(project_root))
    
    # Importiamo il modulo da testare
    import python_wrapper as wrapper
    
    # Importiamo il modulo C reale per i test di integrazione
    import crypto_accelerator as crypto_rust
    
except ImportError as e:
    print(f"\n--- ERRORE DI IMPORT ---")
    print(f"Errore: {e}")
    print(f"Assicurati che 'python-wrapper-fixed.py' e 'crypto_accelerator.so' siano in: {project_root}")
    sys.exit(1)

# --- Costanti di Test ---
AES_KEY_SIZE = wrapper.AES_KEY_SIZE #
AES_NONCE_SIZE = wrapper.AES_NONCE_SIZE #

# --- Fixtures ---

@pytest.fixture
def base_config():
    """Ritorna una configurazione di sicurezza standard."""
    return wrapper.SecurityConfig() #

@pytest.fixture
def crypto_data():
    """Fixture per fornire dati di test comuni (chiave, iv, plaintext)."""
    key = os.urandom(AES_KEY_SIZE)
    iv = os.urandom(AES_NONCE_SIZE)
    plaintext = b"Test del fallback C vs Python" * 10
    return key, iv, plaintext

# --- Test Suite ---

# 1. Test Unitari (Logica interna)

def test_validate_size(base_config):
    """Testa la validazione dei limiti del buffer."""
    crypto = wrapper.SecureCrypto(base_config)
    
    # Test validi
    crypto._validate_size(wrapper.MIN_BUFFER_SIZE)
    crypto._validate_size(wrapper.MAX_BUFFER_SIZE)
    
    # Test non validi
    with pytest.raises(ValueError, match="Invalid buffer size"):
        crypto._validate_size(wrapper.MIN_BUFFER_SIZE - 1)
        
    with pytest.raises(ValueError, match="Invalid buffer size"):
        crypto._validate_size(wrapper.MAX_BUFFER_SIZE + 1)

# 2. Test di Fallback e Selezione Modulo

@patch('python_wrapper.RUST_MODULE_AVAILABLE', True)
def test_mode_c_module_default(crypto_data, base_config):
    """
    Testa la modalità predefinita: RUST_MODULE_AVAILABLE=True, use_hardware_acceleration=True.
    Verifica che il modulo C venga utilizzato.
    """
    key, iv, plaintext = crypto_data
    crypto = wrapper.SecureCrypto(base_config)
    
    assert crypto.use_c is True #
    
    # Eseguiamo un'operazione
    ciphertext, tag = crypto.encrypt_aes_gcm(plaintext, key, iv)
    decrypted = crypto.decrypt_aes_gcm(ciphertext, key, iv, tag)
    
    assert decrypted == plaintext
    assert crypto.stats['rust_module_used'] > 0 #
    assert crypto.stats['python_fallback'] == 0
    assert crypto.stats['errors'] == 0

@patch('python_wrapper.RUST_MODULE_AVAILABLE', False)
def test_mode_python_fallback_module_missing(crypto_data, base_config):
    """
    Testa la modalità fallback: RUST_MODULE_AVAILABLE=False.
    Verifica che venga usato il fallback Python.
    """
    key, iv, plaintext = crypto_data
    crypto = wrapper.SecureCrypto(base_config)
    
    assert crypto.use_c is False #
    
    # Eseguiamo un'operazione
    ciphertext, tag = crypto.encrypt_aes_gcm(plaintext, key, iv)
    decrypted = crypto.decrypt_aes_gcm(ciphertext, key, iv, tag)
    
    assert decrypted == plaintext
    assert crypto.stats['rust_module_used'] == 0
    assert crypto.stats['python_fallback'] > 0 #
    assert crypto.stats['errors'] == 0

@patch('python_wrapper.RUST_MODULE_AVAILABLE', True)
def test_mode_python_fallback_config_disabled(crypto_data):
    """
    Testa la modalità fallback: RUST_MODULE_AVAILABLE=True, ma config.use_hardware_acceleration=False.
    Verifica che venga usato il fallback Python.
    """
    key, iv, plaintext = crypto_data
    config_disabled = wrapper.SecurityConfig(use_hardware_acceleration=False) #
    crypto = wrapper.SecureCrypto(config_disabled)
    
    assert crypto.use_c is False #
    
    # Eseguiamo un'operazione
    ciphertext, tag = crypto.encrypt_aes_gcm(plaintext, key, iv)
    decrypted = crypto.decrypt_aes_gcm(ciphertext, key, iv, tag)
    
    assert decrypted == plaintext
    assert crypto.stats['rust_module_used'] == 0
    assert crypto.stats['python_fallback'] > 0 #
    assert crypto.stats['errors'] == 0

@patch('python_wrapper.crypto_rust.aes_gcm_encrypt', MagicMock(side_effect=Exception("Simulated C Failure")))
@patch('python_wrapper.RUST_MODULE_AVAILABLE', True)
def test_mode_python_fallback_on_c_error(crypto_data, base_config):
    """
    Testa la modalità fallback: Il modulo C è disponibile ma solleva un'eccezione.
    Verifica che il wrapper gestisca l'errore e usi il fallback Python.
    """
    key, iv, plaintext = crypto_data
    crypto = wrapper.SecureCrypto(base_config)
    
    assert crypto.use_c is True
    
    # Eseguiamo la cifratura (che fallirà in C e riproverà in Python)
    ciphertext, tag = crypto.encrypt_aes_gcm(plaintext, key, iv)
    
    # La decifratura (non mockata) userà il C
    decrypted = crypto.decrypt_aes_gcm(ciphertext, key, iv, tag)
    
    assert decrypted == plaintext
    assert crypto.stats['rust_module_used'] > 0 # Ha tentato il C
    assert crypto.stats['python_fallback'] == 1 # Ha usato il fallback
    assert crypto.stats['errors'] == 1 # Ha registrato l'errore C

# 3. Test Secure Key Cache

def test_key_cache_derivation_and_retrieval():
    """Testa che la derivazione KDF popoli la cache e get_key_from_cache la legga."""
    config = wrapper.SecurityConfig(max_key_cache=3) #
    crypto = wrapper.SecureCrypto(config)
    
    password = b"password_segreta_123"
    salt = b"salt_unico_abc"
    
    # 1. Cache è vuota
    assert crypto.get_key_from_cache(password, salt) is None
    
    # 2. Derivazione
    key1 = crypto.derive_key(password, salt)
    
    # 3. Cache è popolata
    assert len(crypto._key_cache) == 1
    key1_cached = crypto.get_key_from_cache(password, salt) #
    
    assert key1 == key1_cached
    
    # --- INIZIO CORREZIONE ---
    # La funzione deve restituire 'bytes', non 'bytearray'
    assert isinstance(key1, bytes)
    # --- FINE CORREZIONE ---
    
    assert len(key1) == AES_KEY_SIZE

@patch('python_wrapper._clear_memory')
def test_key_cache_eviction_fifo(mock_clear_memory):
    """
    Testa che la cache rimuova la chiave più vecchia (FIFO) quando il limite
    (max_key_cache) è raggiunto.
    """
    config = wrapper.SecurityConfig(max_key_cache=2) # Limite stretto
    crypto = wrapper.SecureCrypto(config)
    
    # Dati di test
    p = b"password_valida"
    s1, s2, s3 = b"salt_123", b"salt_456", b"salt_789"
    
    # 1. Aggiungi K1
    key1 = crypto.derive_key(p, s1)
    # Cache: [K1]
    assert len(crypto._key_cache) == 1
    assert crypto.get_key_from_cache(p, s1) is not None
    
    # 2. Aggiungi K2
    key2 = crypto.derive_key(p, s2)
    # Cache: [K1, K2]
    assert len(crypto._key_cache) == 2
    assert crypto.get_key_from_cache(p, s1) is not None
    assert crypto.get_key_from_cache(p, s2) is not None

    # 3. Aggiungi K3 (Questo deve rimuovere K1)
    key3 = crypto.derive_key(p, s3)
    # Cache: [K2, K3]
    assert len(crypto._key_cache) == 2
    
    # K1 non deve più esistere
    assert crypto.get_key_from_cache(p, s1) is None
    # K2 e K3 devono esistere
    assert crypto.get_key_from_cache(p, s2) is not None
    assert crypto.get_key_from_cache(p, s3) is not None

    # 4. Verifica che _clear_memory sia stata chiamata sulla chiave rimossa (K1)
    mock_clear_memory.assert_called_once_with(key1) #

@patch('python_wrapper._clear_memory')
def test_key_cache_clear_on_eviction(mock_clear_memory):
    """
    Testa specificamente che _clear_memory venga invocato 
    correttamente durante l'eviction.
    """
    config = wrapper.SecurityConfig(max_key_cache=1)
    crypto = wrapper.SecureCrypto(config)
    
    key1 = crypto.derive_key(b'pass1_lunga', b'salt1_lungo')
    assert mock_clear_memory.call_count == 0
    
    # Questa chiamata rimuove key1
    key2 = crypto.derive_key(b'pass2_lunga', b'salt2_lungo')
    
    # Verifica che la mock function sia stata chiamata esattamente una volta,
    # e che sia stata chiamata CON l'oggetto key1.
    mock_clear_memory.assert_called_once_with(key1)

# Aggiungiamo un test per la funzione clear_key_cache che abbiamo aggiunto
@patch('python_wrapper._clear_memory')
def test_wrapper_clear_key_cache(mock_clear_memory):
    """
    Testa che clear_key_cache() svuoti la cache e chiami
    _clear_memory per ogni chiave.
    """
    config = wrapper.SecurityConfig(max_key_cache=3)
    crypto = wrapper.SecureCrypto(config)
    
    key1 = crypto.derive_key(b'password_123', b'salt_123')
    key2 = crypto.derive_key(b'password_456', b'salt_456')
    
    assert len(crypto._key_cache) == 2
    assert crypto.get_key_from_cache(b'password_123', b'salt_123') is not None
    
    # Chiama la funzione
    crypto.clear_key_cache()
    
    # Verifica che la cache sia vuota
    assert len(crypto._key_cache) == 0
    assert len(crypto._key_cache_order) == 0
    assert crypto.get_key_from_cache(b'password_123', b'salt_123') is None
    
    # Verifica che _clear_memory sia stata chiamata per entrambe le chiavi
    assert mock_clear_memory.call_count == 2
    mock_clear_memory.assert_any_call(key1)
    mock_clear_memory.assert_any_call(key2)