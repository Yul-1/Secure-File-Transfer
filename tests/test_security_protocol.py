#!/usr/bin/env python3
"""
test_security_protocol.py

Test di integrazione E2E per secure_file_transfer_fixed.py.
Verifica l'handshake, il protocollo (replay, nonce), e il
trasferimento file E2E (happy path, resume, errori).
"""

import pytest
import socket
import threading
import time
import struct
import os
import hashlib
import sys
from typing import Tuple
from pathlib import Path
from collections import deque
from unittest.mock import patch, MagicMock
from datetime import datetime, timedelta

# Importiamo i componenti necessari
try:
    project_root = Path(__file__).parent.parent
    sys.path.insert(0, str(project_root))
    
    from secure_file_transfer_fixed import (
        SecureFileTransferNode, 
        SecureProtocol, 
        SecureKeyManager, 
        HEADER_PACKET_SIZE, 
        HEADER_FORMAT,
        OUTPUT_DIR,
        BUFFER_SIZE
    )
except ImportError as e:
    print(f"Errore di import in test_security_protocol: {e}")
    sys.exit(1)


# --- Fixtures ---

TEST_PORT = 5556
TEST_HOST = '127.0.0.1'
DUMMY_DIR = Path("tests/dummy_files")
DUMMY_DIR.mkdir(exist_ok=True)
OUTPUT_DIR.mkdir(exist_ok=True) # Assicura che la dir di output esista

@pytest.fixture(scope="module")
def secure_server():
    """
    Fixture Pytest per avviare il server in un thread separato.
    'scope="module"' assicura che il server giri per tutti i test in questo file.
    """
    server_node = SecureFileTransferNode(mode='server', host=TEST_HOST, port=TEST_PORT)
    
    server_thread = threading.Thread(target=server_node.start_server, daemon=True)
    server_thread.start()
    
    time.sleep(0.5) # Diamo al server un momento per avviarsi
    
    yield (TEST_HOST, TEST_PORT)
    
    # Cleanup: arresta il server e pulisce i file ricevuti
    server_node.shutdown()
    for f in OUTPUT_DIR.glob("*"):
        os.remove(f)

@pytest.fixture
def dummy_file_factory():
    """
    Fixture che è una factory per creare file dummy di varie dimensioni.
    Pulisce i file creati.
    """
    created_files = []

    def _create_file(filename, size_in_mb):
        file_path = DUMMY_DIR / filename
        data = os.urandom(size_in_mb * 1024 * 1024)
        file_path.write_bytes(data)
        file_hash = hashlib.sha256(data).hexdigest()
        created_files.append(file_path)
        return file_path, file_hash

    yield _create_file

    # Cleanup
    for f in created_files:
        if f.exists():
            os.remove(f)

def perform_client_handshake(host, port) -> Tuple[socket.socket, SecureProtocol]:
    """
    Helper per eseguire un handshake client manuale (LOGICA SIMMETRICA)
    per corrispondere a _perform_secure_handshake
    """
    # 0. Inizializza il KeyManager e il Protocollo lato client
    key_manager = SecureKeyManager('test_client')
    protocol = SecureProtocol(key_manager, deque(maxlen=100))

    # 1. Connessione
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    sock.connect((host, port))
    
    # 2. Esegui l'handshake (SIMMETRICO)
    try:
        header_len = struct.calcsize('!I')
        
        # 1. Invia la chiave pubblica
        public_key_pem = key_manager.get_public_key_pem()
        sock.sendall(struct.pack('!I', len(public_key_pem)) + public_key_pem)

        # 2. Ricevi la chiave pubblica del server
        header = sock.recv(4)
        if not header: raise ConnectionError("Handshake failed: no peer key header")
        peer_key_len, = struct.unpack('!I', header)
        peer_key_pem = sock.recv(peer_key_len)
        if not peer_key_pem: raise ConnectionError("Handshake failed: no peer key")

        # 3. Stabilisci e invia il segreto
        encrypted_secret = key_manager.establish_shared_secret(peer_key_pem)
        sock.sendall(struct.pack('!I', len(encrypted_secret)) + encrypted_secret)
        
        # 4. Ricevi conferma
        confirm_header = sock.recv(4)
        if not confirm_header: raise ConnectionError("Handshake failed: no auth header")
        confirm_len, = struct.unpack('!I', confirm_header)
        confirm_msg = sock.recv(confirm_len)
        
        if confirm_msg != b"AUTH_OK":
            raise ConnectionError(f"Handshake failed: invalid auth response {confirm_msg}")
            
        return sock, protocol

    except Exception as e:
        sock.close()
        pytest.fail(f"Client handshake helper failed: {e}")

def read_and_parse_packet(sock, protocol, client_id="test_client"):
    """Helper per leggere un pacchetto completo (Header + Payload)"""
    header = sock.recv(HEADER_PACKET_SIZE)
    if not header:
        raise ConnectionAbortedError("Server closed connection")
    
    _magic, _ver, _type, _offset, payload_len, *_ = struct.unpack(HEADER_FORMAT, header)
    
    ciphertext = b''
    while len(ciphertext) < payload_len:
        chunk = sock.recv(payload_len - len(ciphertext))
        if not chunk:
            raise ConnectionAbortedError("Server closed connection during payload")
        ciphertext += chunk
    
    full_packet = header + ciphertext
    return protocol.parse_packet(full_packet, client_id)


# --- Test Cases ---

### 1. Test di Protocollo (Nonce, Replay)

def test_nonce_uniqueness(secure_server):
    """
    TEST 1: Verifica che due pacchetti consecutivi usino Nonce diversi.
    """
    host, port = secure_server
    sock, protocol = perform_client_handshake(host, port)
    
    try:
        # Crea e invia il primo pacchetto
        packet1_bytes = protocol._create_json_packet('ping', {})
        sock.sendall(packet1_bytes)
        
        # Crea e invia il secondo pacchetto
        packet2_bytes = protocol._create_json_packet('ping', {})
        sock.sendall(packet2_bytes)
        
        try:
            # Leggi pong 1
            read_and_parse_packet(sock, protocol)
            # Leggi pong 2
            read_and_parse_packet(sock, protocol)
        except Exception as e:
            pytest.fail(f"Fallimento durante la pulizia dei pong: {e}")

        # Estrai i nonce dall'header
        # Offset: magic(4) + ver(4) + type(1) + offset(8) + len(4) + key_id(16) = 37
        nonce1_offset = 37
        nonce1 = packet1_bytes[nonce1_offset : nonce1_offset + 12]
        nonce2 = packet2_bytes[nonce1_offset : nonce1_offset + 12]
        
        assert len(nonce1) == 12
        assert len(nonce2) == 12
        assert nonce1 != nonce2, "I Nonce sono identici! Fallimento AES-GCM."

    finally:
        sock.close()

def test_replay_attack_detection(secure_server):
    """
    TEST 2: Verifica che il server rilevi e blocchi un Replay Attack.
    """
    host, port = secure_server
    sock, protocol = perform_client_handshake(host, port)
    
    try:
        # Crea e invia il pacchetto valido
        valid_packet = protocol._create_json_packet('ping', {})
        sock.sendall(valid_packet)
        
        # Aspetta la risposta PONG per essere sicuri che il server lo abbia processato
        pkt_type, payload, offset = read_and_parse_packet(sock, protocol)
        assert pkt_type == 'json' and payload['type'] == 'pong'

        # Ora, invia DI NUOVO lo stesso identico pacchetto
        sock.sendall(valid_packet)
        
        # Il server dovrebbe rilevare il replay (ValueError) e chiudere la connessione.
        # Un 'recv' su un socket chiuso restituirà b''
        time.sleep(0.2) 
        data = sock.recv(1024)
        
        assert data == b'', "Il server non ha chiuso la connessione dopo un replay attack"

    finally:
        sock.close()


### 2. Test di Integrazione E2E (Happy Path, Resume)

def test_e2e_happy_path_single_file(secure_server, dummy_file_factory):
    """TEST 3: Trasferimento E2E di un file (1MB)."""
    host, port = secure_server
    file_path, original_hash = dummy_file_factory("test_1mb.bin", 1)
    
    client_node = None
    try:
        client_node = SecureFileTransferNode(mode='client')
        client_node.connect_to_server(host, port)
        client_node.send_file(str(file_path))
    except Exception as e:
        pytest.fail(f"Trasferimento E2E fallito: {e}")
    finally:
        if client_node:
            client_node.shutdown()
            
    # Verifica sul lato server
    received_path = OUTPUT_DIR / file_path.name
    assert received_path.exists(), "Il file non è stato ricevuto dal server"
    
    received_hash = hashlib.sha256(received_path.read_bytes()).hexdigest()
    assert received_hash == original_hash, "L'hash del file ricevuto non corrisponde"

def test_e2e_happy_path_multi_chunk(secure_server, dummy_file_factory):
    """TEST 4: Trasferimento E2E di un file > BUFFER_SIZE (es. 5MB)."""
    host, port = secure_server
    # BUFFER_SIZE è 4096, creiamo un file da 5MB
    file_path, original_hash = dummy_file_factory("test_5mb.bin", 5)
    
    client_node = None
    try:
        client_node = SecureFileTransferNode(mode='client')
        client_node.connect_to_server(host, port)
        client_node.send_file(str(file_path))
    finally:
        if client_node:
            client_node.shutdown()
            
    # Verifica sul lato server
    received_path = OUTPUT_DIR / file_path.name
    assert received_path.exists()
    received_hash = hashlib.sha256(received_path.read_bytes()).hexdigest()
    assert received_hash == original_hash, "L'hash del file multi-chunk non corrisponde"

def test_e2e_resume_transfer(secure_server, dummy_file_factory):
    """TEST 5: Verifica la logica di ripresa del trasferimento."""
    host, port = secure_server
    file_path, original_hash = dummy_file_factory("test_resume.bin", 1)
    file_size = file_path.stat().st_size
    
    # 1. Connessione 1: Invia Header e 2 Chunks, poi disconnetti
    try:
        sock, protocol = perform_client_handshake(host, port)
        
        # Invia Header
        header_payload = {'filename': file_path.name, 'total_size': file_size}
        header_packet = protocol._create_json_packet('file_header', header_payload)
        sock.sendall(header_packet)
        
        # Ricevi ACK (offset 0)
        pkt_type, payload, _ = read_and_parse_packet(sock, protocol)
        assert payload['payload']['offset'] == 0
        
        # Invia 2 chunks
        chunk1 = b"A" * BUFFER_SIZE
        chunk2 = b"B" * BUFFER_SIZE
        sock.sendall(protocol._create_data_packet(chunk1, 0))
        sock.sendall(protocol._create_data_packet(chunk2, BUFFER_SIZE))
        
        time.sleep(0.1) # Dai al server il tempo di scrivere
        sock.close()
    except Exception as e:
        pytest.fail(f"Parte 1 (invio parziale) fallita: {e}")
        
    # 2. Connessione 2: Riconnetti e invia lo stesso file header
    expected_offset = BUFFER_SIZE * 2
    try:
        sock, protocol = perform_client_handshake(host, port)
        
        # Invia Header
        header_payload = {'filename': file_path.name, 'total_size': file_size}
        header_packet = protocol._create_json_packet('file_header', header_payload)
        sock.sendall(header_packet)
        
        # Ricevi ACK (offset 0)
        pkt_type, payload, _ = read_and_parse_packet(sock, protocol)
        
        # Verifica che il server richieda la ripresa dall'offset corretto
        assert payload['type'] == 'file_resume_ack'
        assert payload['payload']['offset'] == expected_offset
        
        sock.close()
    except Exception as e:
        pytest.fail(f"Parte 2 (verifica resume) fallita: {e}")


### 3. Test di Integrazione E2E (Errori Protocollo)

@patch('secure_file_transfer_fixed.SecureKeyManager.sign_data')
def test_e2e_protocol_invalid_signature(mock_sign, secure_server):
    """TEST 6: Verifica che il server rifiuti una firma non valida."""
    host, port = secure_server
    
    # Simula una firma HMAC non valida
    mock_sign.return_value = b'\x00' * 32
    
    sock, protocol = perform_client_handshake(host, port)
    
    try:
        # Crea e invia un pacchetto 'ping'. sign_data sarà mockato.
        ping_packet = protocol._create_json_packet('ping', {})
        sock.sendall(ping_packet)
        
        # Il server (protocol.parse_packet) dovrebbe rilevare l'errore
        # e chiudere la connessione.
        time.sleep(0.2)
        data = sock.recv(1024)
        assert data == b'', "Il server non ha chiuso la connessione per firma non valida"
        
    finally:
        sock.close()

@patch('secure_file_transfer_fixed.datetime')
def test_e2e_protocol_expired_timestamp(mock_datetime, secure_server):
    """TEST 7: Verifica che il server rifiuti un timestamp scaduto."""
    host, port = secure_server
    
    # Simula che 'datetime.now()' restituisca 10 minuti fa
    mock_datetime.now.return_value = datetime.now() - timedelta(minutes=10)
    
    sock, protocol = perform_client_handshake(host, port)
    
    try:
        # Crea e invia un pacchetto 'ping'. Il timestamp sarà vecchio.
        ping_packet = protocol._create_json_packet('ping', {})
        sock.sendall(ping_packet)
        
        # Il server (protocol.parse_packet) dovrebbe rilevare l'errore
        # e chiudere la connessione.
        time.sleep(0.2)
        data = sock.recv(1024)
        assert data == b'', "Il server non ha chiuso la connessione per timestamp scaduto"
        
    finally:
        sock.close()
        # Ripristina il mock
        mock_datetime.now.return_value = datetime.now()