#!/usr/bin/env python3
"""
Suite di Test P1 (Importanti - Robustezza) per AegisTransfer
Team: _team controllo
(Versione 1.4: Corretto errore 'AttributeError' in test_p1_max_global_connections)
"""

import pytest
import threading
import time
import socket
import logging
import re
from pathlib import Path
from typing import Tuple, Generator, List, Any
from unittest.mock import patch, MagicMock

# Importa le classi necessarie dal codice sorgente
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

try:
    from sft import (
        SecureFileTransferNode,
        SecureKeyManager,
        SecureProtocol,
        RateLimiter,
        MAX_GLOBAL_CONNECTIONS,
        OUTPUT_DIR,
        BUFFER_SIZE
    )
except ImportError as e:
    print(f"Errore: Impossibile importare 'secure_file_transfer_fixed.py'. Assicurati che sia nel PYTHONPATH.")
    print(f"Dettagli: {e}")
    sys.exit(1)


# --- Fixtures ---
# Rimosse. Si affida a conftest.py


# --- Test P1 (Importanti - Robustezza) ---

@patch('time.time') # Mock time.time()
def test_p1_ratelimiter_cleanup(mock_time):
    """
    P1.1: Verifica che il RateLimiter elimini i client vecchi
    per prevenire memory leak.
    """
    print(f"\n--- test_p1_ratelimiter_cleanup (no freezegun) ---")
    
    limiter = RateLimiter(max_requests=10, window_seconds=60)
    
    client_stale = "1.1.1.1"
    client_active = "2.2.2.2"
    
    mock_time.return_value = 1000.0
    assert limiter.is_allowed(client_stale)
    assert limiter.last_seen[client_stale] == 1000.0

    mock_time.return_value = 8200.0
    assert limiter.is_allowed(client_active)
    assert limiter.last_seen[client_active] == 8200.0
    
    print("Prima del cleanup: ", limiter.last_seen.keys())
    
    limiter.cleanup(older_than=3600)
    
    print("Dopo il cleanup: ", limiter.last_seen.keys())

    assert client_stale not in limiter.requests, "Client 'stale' non rimosso da 'requests'"
    assert client_stale not in limiter.last_seen, "Client 'stale' non rimosso da 'last_seen'"
    assert client_active in limiter.requests, "Client 'active' rimosso erroneamente"
    
    print("Test P1.1 (RateLimiter Cleanup) completato: Prevenzione memory leak verificata.")
    limiter.shutdown()

def test_p1_max_global_connections(persistent_server: SecureFileTransferNode, monkeypatch: pytest.MonkeyPatch):
    """
    P1.2: Verifica che il server rifiuti connessioni oltre
    MAX_GLOBAL_CONNECTIONS.
    (FIX 2.1: Rimosso setattr sull'istanza del server)
    """
    print(f"\n--- test_p1_max_global_connections ---")
    
    # Patcha il limite globale per questo test
    max_conn = 5
    monkeypatch.setattr(
        'sft.MAX_GLOBAL_CONNECTIONS',
        max_conn
    )
    # (FIX 2.1) Rimosso:
    # monkeypatch.setattr(persistent_server, 'MAX_GLOBAL_CONNECTIONS', max_conn)
    
    print(f"Limite connessioni per questo test: {max_conn}")

    active_clients: List[SecureFileTransferNode] = []
    
    try:
        print(f"Saturazione connessioni (0/{max_conn})...")
        for i in range(max_conn):
            client = SecureFileTransferNode(mode='client')
            client.connect_to_server('127.0.0.1', persistent_server.port)
            active_clients.append(client)
            print(f"Client {i+1}/{max_conn} connesso.")
            time.sleep(0.05) 
        
        time.sleep(0.5) 
        print(f"Contatore connessioni server: {persistent_server._connection_counter}")
        
        print("Tento connessione client extra (dovrebbe essere rifiutata)...")
        extra_client = SecureFileTransferNode(mode='client')
        
        # Il server (ora _handle_connection) dovrebbe chiudere il socket.
        with pytest.raises((ConnectionRefusedError, ConnectionResetError, ConnectionAbortedError)):
            extra_client.connect_to_server('127.0.0.1', persistent_server.port)
            
        print("Connessione extra fallita come previsto.")
        
    finally:
        print("Chiudo connessioni attive...")
        for client in active_clients:
            client.shutdown()
        time.sleep(1)

    print("Test P1.2 (MAX_GLOBAL_CONNECTIONS) completato: Limite rispettato.")


def test_p1_large_file_offset_handling(
    connected_client: SecureFileTransferNode, 
    monkeypatch: pytest.MonkeyPatch, 
    tmp_path: Path, 
    caplog: pytest.LogCaptureFixture,
    server_output_dir: Path # (FIX 2.0) Inietta fixture
):
    """
    P1.4: Verifica che il protocollo gestisca offset > 32-bit (es. 4.5GB)
    """
    print(f"\n--- test_p1_large_file_offset_handling ---")
    client = connected_client
    
    fake_total_size = 5_000_000_000 # 5 GB
    fake_offset = 4_500_000_000 # 4.5 GB
    
    file_path = tmp_path / "large_file.bin"
    file_data = b"DATA_CHUNK" # 10 byte
    file_path.write_bytes(file_data)
    
    original_json_packet = client.protocol._create_json_packet
    original_data_packet = client.protocol._create_data_packet

    def patch_json_packet(msg_type: str, payload: dict, sign: bool = True) -> bytes:
        if msg_type == 'file_header':
            print(f"[Monkeypatch] Modifico file_header (Size: {fake_total_size})")
            payload['total_size'] = fake_total_size
        return original_json_packet(msg_type, payload, sign)

    def patch_data_packet(data: bytes, offset: int) -> bytes:
        print(f"[Monkeypatch] Modifico data_packet (Offset: {fake_offset})")
        monkeypatch.setattr(client.protocol, "_create_data_packet", original_data_packet)
        return original_data_packet(data, fake_offset)
        
    monkeypatch.setattr(client.protocol, "_create_json_packet", patch_json_packet)
    monkeypatch.setattr(client.protocol, "_create_data_packet", patch_data_packet)

    print("Avvio upload con offset > 4GB...")
    
    with caplog.at_level(logging.ERROR):
        client.send_file(str(file_path))
    
    server_file_path = server_output_dir / file_path.name
    assert server_file_path.exists()
    
    assert server_file_path.stat().st_size == fake_offset + len(file_data)
    
    client_logs = [rec.message for rec in caplog.records]
    expected_log = "Peer reported error in final ACK: Hash mismatch on server"
    assert any(expected_log in msg for msg in client_logs), \
        f"Il client non ha loggato l'errore di hash mismatch. Log: {client_logs}"
    
    server_file_path.unlink()
    print("Test P1.4 (Offset 64-bit) completato: Errore hash mismatch (atteso) rilevato.")

def test_p1_logging_sanitization(caplog: pytest.LogCaptureFixture):
    """
    P1.5: Verifica che le chiavi e i segreti non
    finiscano mai nei log.
    """
    print(f"\n--- test_p1_logging_sanitization ---")
    
    client = SecureFileTransferNode(mode='client')
    
    km = client.key_manager
    km.shared_secret = b"MY_SUPER_SECRET_HMAC_KEY_32BYTES"
    km.current_key = b"MY_SUPER_SECRET_AES_KEY_32BYTES"
    
    secret_hex = km.shared_secret.hex()
    key_hex = km.current_key.hex()
    
    print(f"Segreti (non loggare): {secret_hex[:5]}... / {key_hex[:5]}...")
    
    caplog.clear()
    with caplog.at_level(logging.DEBUG):
        client.shutdown()
        
    all_logs = caplog.text
    
    assert not re.search(secret_hex[2:10], all_logs, re.IGNORECASE), \
        "Trovato LEAK di shared_secret nei log!"
    assert not re.search(key_hex[2:10], all_logs, re.IGNORECASE), \
        "Trovato LEAK di current_key nei log!"
        
    print("Test P1.5 (Logging Sanitization) completato: Nessun leak di segreti rilevato.")