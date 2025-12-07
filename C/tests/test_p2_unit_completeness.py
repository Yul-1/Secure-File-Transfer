#!/usr/bin/env python3
"""
Suite di Test P2 (Unit Test di Completezza) per AegisTransfer
Team: _team controllo
(Versione 1.1: Rimosso marker timeout)
"""

import pytest
import threading
import time
import socket
import logging
import os
import struct
import json
from pathlib import Path
from typing import Tuple, Generator, List, Any
from collections import deque
from unittest.mock import patch, MagicMock
from freezegun import freeze_time

# --- Configurazione Path ---
import sys
try:
    project_root = Path(__file__).parent.parent
    sys.path.insert(0, str(project_root))
    
    from sft import (
        SecureKeyManager,
        SecureProtocol,
        SecureFileTransferNode,
        HEADER_FORMAT,
        HEADER_PACKET_SIZE,
        MAX_PACKET_SIZE,
        PROTOCOL_VERSION,
        OUTPUT_DIR
    )
except ImportError as e:
    print(f"\n--- ERRORE DI IMPORT ---")
    print(f"Errore: {e}")
    print(f"Assicurati che 'sft.py' sia in: {project_root}")
    sys.exit(1)


# --- Fixtures ---

@pytest.fixture
def key_manager() -> SecureKeyManager:
    """Fixture per un SecureKeyManager pulito."""
    return SecureKeyManager("test_manager")

@pytest.fixture
def protocol(key_manager: SecureKeyManager) -> SecureProtocol:
    """Fixture per un SecureProtocol con un key_manager e una coda anti-replay."""
    replay_queue = deque(maxlen=100)
    return SecureProtocol(key_manager, replay_queue)

# --- Test Categoria 2 (SecureKeyManager) ---

def test_p2_keymanager_add_external_key(key_manager: SecureKeyManager):
    """
    (CAT 2) Testa add_external_key_to_cache()
    """
    print(f"\n--- test_p2_keymanager_add_external_key ---")
    
    external_key = os.urandom(32)
    external_key_id = "test_external_id_123"
    
    assert key_manager.get_key_by_id(external_key_id) is None
    key_manager.add_external_key_to_cache(external_key, external_key_id)
    retrieved_key = key_manager.get_key_by_id(external_key_id)
    assert retrieved_key is not None
    assert retrieved_key == external_key
    
    key_manager.add_external_key_to_cache(os.urandom(32), external_key_id)
    assert len(key_manager.previous_keys) == 1

def test_p2_keymanager_auth_without_secret(key_manager: SecureKeyManager):
    """
    (CAT 2) Testa verify_signature() e sign_data() quando lo
    shared_secret non è stabilito.
    """
    print(f"\n--- test_p2_keymanager_auth_without_secret ---")
    
    with pytest.raises(ValueError, match="Shared secret not established"):
        key_manager.sign_data(b"data_to_sign")
        
    result = key_manager.verify_signature(b"data", b"fake_sig")
    assert result is False

# --- Test Categoria 3 (SecureProtocol) ---

def test_p2_protocol_parse_packet_invalid_magic(protocol: SecureProtocol):
    """
    (CAT 3) Testa parse_packet() con un Magic Number errato.
    """
    print(f"\n--- test_p2_protocol_parse_packet_invalid_magic ---")
    
    invalid_header = struct.pack(
        HEADER_FORMAT,
        b'BAD!', # Magic errato
        2, 0x01, 0, 100,
        b'key_id'.ljust(16, b'\x00'),
        b'nonce'.ljust(12, b'\x00'),
        b'tag'.ljust(16, b'\x00')
    )
    
    with pytest.raises(ValueError, match="Invalid magic number"):
        protocol.parse_packet(invalid_header + b"payload", "client_id")

def test_p2_protocol_parse_packet_unsupported_version(protocol: SecureProtocol):
    """
    (CAT 3) Testa parse_packet() con una versione protocollo non supportata.
    """
    print(f"\n--- test_p2_protocol_parse_packet_unsupported_version ---")
    
    invalid_header = struct.pack(
        HEADER_FORMAT,
        b'SFTP',
        99, # Versione non supportata
        0x01, 0, 100,
        b'key_id'.ljust(16, b'\x00'),
        b'nonce'.ljust(12, b'\x00'),
        b'tag'.ljust(16, b'\x00')
    )
    
    with pytest.raises(ValueError, match="Unsupported protocol version: 99"):
        protocol.parse_packet(invalid_header + b"payload", "client_id")

@freeze_time("2024-01-01 12:00:00")
def test_p2_protocol_parse_packet_invalid_timestamp(protocol: SecureProtocol, key_manager: SecureKeyManager):
    """
    (CAT 3) Testa la validazione del timestamp (troppo vecchio o futuro).
    """
    print(f"\n--- test_p2_protocol_parse_packet_invalid_timestamp ---")
    
    key_manager.generate_session_key()
    
    old_timestamp = "2024-01-01T11:50:00"
    with patch.object(protocol, '_check_and_add_message', return_value=True):
        with patch.object(protocol, '_validate_sequence_number', return_value=True):
            message_bytes = json.dumps({
                'type': 'ping', 'version': PROTOCOL_VERSION,
                'payload': {}, 'timestamp': old_timestamp, 'seq': 0
            }).encode('utf-8')

            nonce = os.urandom(12)
            key_id_bytes = key_manager.key_id.encode().ljust(16, b'\x00')
            aad = struct.pack('!4sI B Q I 16s 12s', b'SFTP', 2, 0x01, 0, len(message_bytes),
                            key_id_bytes, nonce)
            ciphertext, key_id, nonce, tag = protocol.encrypt_data(message_bytes, nonce=nonce, aad=aad)
            header = struct.pack(HEADER_FORMAT, b'SFTP', 2, 0x01, 0, len(ciphertext),
                                key_id_bytes, nonce, tag)

            with pytest.raises(ValueError, match="Invalid timestamp"):
                protocol.parse_packet(header + ciphertext, "client_id")

    # 2. Timestamp futuro (10 minuti nel futuro)
    future_timestamp = "2024-01-01T12:10:00"
    with patch.object(protocol, '_check_and_add_message', return_value=True):
        with patch.object(protocol, '_validate_sequence_number', return_value=True):
            message_bytes = json.dumps({
                'type': 'ping', 'version': PROTOCOL_VERSION,
                'payload': {}, 'timestamp': future_timestamp, 'seq': 1
            }).encode('utf-8')

            nonce = os.urandom(12)
            key_id_bytes = key_manager.key_id.encode().ljust(16, b'\x00')
            aad = struct.pack('!4sI B Q I 16s 12s', b'SFTP', 2, 0x01, 0, len(message_bytes),
                            key_id_bytes, nonce)
            ciphertext, key_id, nonce, tag = protocol.encrypt_data(message_bytes, nonce=nonce, aad=aad)
            header = struct.pack(HEADER_FORMAT, b'SFTP', 2, 0x01, 0, len(ciphertext),
                                key_id_bytes, nonce, tag)

            with pytest.raises(ValueError, match="Invalid timestamp"):
                protocol.parse_packet(header + ciphertext, "client_id")

def test_p2_protocol_create_packet_too_large(protocol: SecureProtocol, key_manager: SecureKeyManager):
    """
    (CAT 3) Testa _create_json_packet() con payload troppo grande.
    """
    print(f"\n--- test_p2_protocol_create_packet_too_large ---")
    key_manager.generate_session_key()
    
    try:
        large_payload = {'data': 'A' * (MAX_PACKET_SIZE + 100)}
    except (MemoryError, OverflowError):
        pytest.skip("Impossibile allocare memoria per il test (payload troppo grande)")
    
    with pytest.raises(ValueError, match="Packet too large"):
        protocol._create_json_packet('file_header', large_payload)
        

# --- Test Categoria 11 (Edge Cases Filesystem) ---

def test_p2_filesystem_readonly_directory(tmp_path: Path, caplog: pytest.LogCaptureFixture):
    """
    (CAT 11) Testa il comportamento del server quando OUTPUT_DIR è read-only.
    """
    print(f"\n--- test_p2_filesystem_readonly_directory ---")

    readonly_dir = tmp_path / "readonly_output"
    readonly_dir.mkdir()
    readonly_dir.chmod(0o555)
    
    server = SecureFileTransferNode(mode='server', host='127.0.0.1', port=0)
    
    # Patcha la costante OUTPUT_DIR *prima* che il server la usi
    with patch('sft.OUTPUT_DIR', readonly_dir):
        
        server_thread = threading.Thread(target=server.start_server, daemon=True)
        server_thread.start()
        
        timeout = time.time() + 5
        while server.port == 0 and time.time() < timeout:
            time.sleep(0.01) 
        assert server.port != 0, "Server non partito"

        client = SecureFileTransferNode(mode='client')
        try:
            client.connect_to_server('127.0.0.1', server.port)
            
            upload_file_path = tmp_path / "upload.txt"
            upload_file_path.write_bytes(b"test data")
            
            print("Tento l'upload su directory read-only...")
            
            with caplog.at_level(logging.INFO):
                with pytest.raises((ConnectionAbortedError, ConnectionResetError, BrokenPipeError)):
                    client.send_file(str(upload_file_path))
            
            assert readonly_dir.exists()
            files_in_dir = list(readonly_dir.glob('*'))
            assert len(files_in_dir) == 0, "File creato erroneamente in dir read-only"

            print("Test P2.11 (Read-Only FS) completato: Connessione chiusa come previsto.")

        finally:
            client.shutdown()
            server.shutdown()
            server_thread.join(2)
            readonly_dir.chmod(0o755)