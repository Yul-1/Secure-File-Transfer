#!/usr/bin/env python3
"""
test_unit_sft.py

Unit test per la logica interna di secure_file_transfer_fixed.py.
Testa classi come RateLimiter, SecureKeyManager e funzioni 
come sanitize_filename in isolamento.
"""

import pytest
import time
import os
import hashlib
from collections import deque
from unittest.mock import patch, MagicMock
from datetime import datetime, timedelta

# Importa i componenti dal modulo principale
# (Assumendo che questo file sia in 'tests/' e il main in root)
import sys
from pathlib import Path

try:
    project_root = Path(__file__).parent.parent
    sys.path.insert(0, str(project_root))
    
    from sft import (
        RateLimiter, 
        SecureKeyManager, 
        SecureProtocol,
        MAX_REQUESTS_PER_WINDOW,
        RATE_LIMIT_WINDOW
    )
except ImportError as e:
    print(f"Errore di import in test_unit_sft: {e}")
    sys.exit(1)


# --- Test Suite ---

### 1. Test RateLimiter
def test_ratelimiter_allows_burst():
    """Verifica che il limiter permetta un burst di richieste."""
    limiter = RateLimiter(max_requests=5, window_seconds=10)
    client_id = "client_1"
    
    for _ in range(5):
        assert limiter.is_allowed(client_id) is True

def test_ratelimiter_blocks_when_exceeded():
    """Verifica che il limiter blocchi dopo il burst."""
    limiter = RateLimiter(max_requests=5, window_seconds=10)
    client_id = "client_1"
    
    for _ in range(5):
        assert limiter.is_allowed(client_id) is True
        
    # La sesta richiesta deve fallire
    assert limiter.is_allowed(client_id) is False

@patch('time.time')
def test_ratelimiter_resets_after_window(mock_time):
    """Verifica che il limite si resetti dopo la finestra temporale."""
    limiter = RateLimiter(max_requests=5, window_seconds=10)
    client_id = "client_1"
    
    # Simula 5 richieste all'inizio
    mock_time.return_value = 1000.0
    for _ in range(5):
        limiter.is_allowed(client_id)
    
    # La sesta richiesta (allo stesso tempo) fallisce
    assert limiter.is_allowed(client_id) is False
    
    # Spostiamo il tempo avanti di 11 secondi (oltre la finestra di 10)
    mock_time.return_value = 1011.0
    
    # La richiesta ora dovrebbe passare
    assert limiter.is_allowed(client_id) is True
    # E il contatore dovrebbe essere 1 (non 6)
    assert len(limiter.requests[client_id]) == 1


### 2. Test sanitize_filename
@pytest.fixture
def protocol_instance():
    # Serve un'istanza di SecureProtocol per chiamare sanitize_filename
    # (Potremmo anche renderla statica, ma per ora va bene)
    km = SecureKeyManager("test_identity")
    return SecureProtocol(km, deque())

def test_sanitize_path_traversal(protocol_instance):
    """Test per prevenire Path Traversal."""
    # os.path.basename è il primo
    assert protocol_instance.sanitize_filename("../../etc/passwd") == "passwd"
    assert protocol_instance.sanitize_filename("C:\\Windows\\System32") == "CWindowsSystem32"
    # Test con caratteri non validi rimossi da re.sub
    assert protocol_instance.sanitize_filename("file*?<>.txt") == "file.txt"

def test_sanitize_reserved_names(protocol_instance):
    """Test per nomi riservati Windows."""
    assert protocol_instance.sanitize_filename("CON") == "safe_CON"
    assert protocol_instance.sanitize_filename("prn.txt") == "safe_prn.txt"
    assert protocol_instance.sanitize_filename("nul") == "safe_nul"

def test_sanitize_long_filename(protocol_instance):
    """Test per nomi file eccessivamente lunghi."""
    long_name = "a" * 300 + ".txt"
    sanitized = protocol_instance.sanitize_filename(long_name)
    assert len(sanitized) <= 255
    # 🟢 FIX (Analisi #5 Test): La nuova logica (corretta)
    # tronca a (255 - len(ext)), che è 251.
    assert sanitized == ("a" * 251) + ".txt"


### 3. Test SecureKeyManager
def test_keymanager_handshake_symmetric():
    """Testa che due manager possano stabilire un segreto condiviso usando ECDH (X25519)."""

    manager_client = SecureKeyManager("client")
    manager_server = SecureKeyManager("server")

    # 1. Generazione e scambio delle chiavi pubbliche X25519
    client_pub_bytes = manager_client.generate_ephemeral_key()
    server_pub_bytes = manager_server.generate_ephemeral_key()

    # 2. Entrambi computano il segreto condiviso usando la chiave pubblica dell'altro
    manager_client.compute_shared_secret(server_pub_bytes)
    manager_server.compute_shared_secret(client_pub_bytes)

    # 3. Verifica che entrambi abbiano derivato lo stesso segreto condiviso
    assert manager_client.shared_secret is not None
    assert manager_server.shared_secret is not None

    # Devono avere lo stesso segreto HMAC e la stessa chiave AES
    assert manager_client.shared_secret == manager_server.shared_secret
    assert manager_client.current_key == manager_server.current_key

def test_keymanager_key_rotation_eviction():
    """Testa che la rotazione delle chiavi (session_key) rimuova le vecchie."""
    
    # Il costruttore imposta maxlen=3
    manager = SecureKeyManager("test")
    assert manager.previous_keys.maxlen == 3
    
    # Genera K1 (diventa current)
    key1, id1 = manager.generate_session_key()
    assert manager.current_key == key1
    assert len(manager.previous_keys) == 0
    
    # Genera K2 (K1 va in previous)
    key2, id2 = manager.generate_session_key()
    assert manager.current_key == key2
    assert len(manager.previous_keys) == 1
    
    # Genera K3 (K2 va in previous)
    key3, id3 = manager.generate_session_key()
    assert manager.current_key == key3
    assert len(manager.previous_keys) == 2

    # Genera K4 (K3 va in previous, il buffer è pieno)
    key4, id4 = manager.generate_session_key()
    assert manager.current_key == key4
    assert len(manager.previous_keys) == 3 # K1, K2, K3
    
    # Genera K5 (K4 va in previous, K1 viene Rimosso)
    key5, id5 = manager.generate_session_key()
    assert manager.current_key == key5
    assert len(manager.previous_keys) == 3 # K2, K3, K4
    
    # K1 non deve più esistere
    assert manager.get_key_by_id(id1) is None
    # K2, K3, K4 devono esistere
    assert manager.get_key_by_id(id2) == key2
    assert manager.get_key_by_id(id3) == key3
    assert manager.get_key_by_id(id4) == key4