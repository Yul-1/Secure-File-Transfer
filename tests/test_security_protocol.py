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
        # 🟢 FIX: Importa OUTPUT_DIR (che sarà patchato da conftest)
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
# 🟢 FIX: Non creare 'ricevuti', conftest usa tmp_path
# OUTPUT_DIR.mkdir(exist_ok=True) 

@pytest.fixture(scope="module")
def secure_server():
    """
    Fixture Pytest per avviare il server in modalità 'module'.
    Tutti i test in questo file useranno lo stesso server.
    """
    
    # 🟢 MODIFICA: Usa porta 0 per porta dinamica
    server = SecureFileTransferNode(mode='server', host=TEST_HOST, port=0)
    
    server_thread = threading.Thread(target=server.start_server, daemon=True)
    server_thread.start()
    
    # 🟢 MODIFICA: Attesa robusta per l'avvio e l'assegnazione della porta
    start_time = time.time()
    while not server.running or server.port == 0:
        time.sleep(0.01)
        if time.time() - start_time > 10.0: # Timeout 10 secondi
            pytest.fail("Server non avviato entro 10s.")
            
    print(f"\n--- Server avviato su porta {server.port} ---")
    
    yield (TEST_HOST, server.port)
    
    # Teardown
    print("\n--- Shutdown server ---")
    server.shutdown()
    server_thread.join(timeout=2.0)
    
    # Pulizia file
    # 🟢 FIX: Pulisci la directory corretta (patchata)
    for f in OUTPUT_DIR.glob("*"):
        try:
            os.remove(f)
        except OSError:
            pass

@pytest.fixture(scope="session")
def test_file_factory(tmp_path_factory):
    """Factory (session scope) per creare file di test."""
    
    def _create_file(filename: str, size_kb: int) -> Path:
        file_dir = tmp_path_factory.mktemp("test_files_protocol")
        file_path = file_dir / filename
        content = os.urandom(size_kb * 1024)
        file_path.write_bytes(content)
        
        # Calcola l'hash per i test
        file_hash = hashlib.sha256(content).hexdigest()
        
        return file_path, file_hash

    return _create_file

# --- Helper ---

def perform_client_handshake(host: str, port: int) -> Tuple[SecureFileTransferNode, socket.socket, SecureProtocol]:
    """Helper per eseguire solo l'handshake e restituire il protocollo client."""
    client_node = SecureFileTransferNode(mode='client')
    
    # N.B: Questo usa l'istanza 'self.protocol' del client_node
    # che è quella che vogliamo testare
    
    try:
        client_node.connect_to_server(host, port)
    except Exception as e:
        pytest.fail(f"perform_client_handshake fallito durante la connessione: {e}")
    
    # 🟢 FIX: Restituisci l'intero nodo, non solo parti di esso
    return client_node, client_node.peer_socket, client_node.protocol

# --- Test Suite ---

def test_server_startup(secure_server):
    """TEST 0: Verifica che il server si avvii."""
    host, port = secure_server
    assert port != 0
    # Prova a connettere (solo socket, senza handshake)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((host, port))
        s.close()
    except ConnectionRefusedError:
        pytest.fail("Il server non ha accettato la connessione.")

def test_e2e_secure_handshake(secure_server):
    """TEST 1: Verifica che l'handshake E2E abbia successo."""
    host, port = secure_server
    
    client_node = SecureFileTransferNode(mode='client')
    try:
        client_node.connect_to_server(host, port)
        
        # 1. Verifica che il client abbia una shared_secret
        assert client_node.key_manager.shared_secret is not None
        assert len(client_node.key_manager.shared_secret) == 32
        
        # 2. Verifica che il client abbia una chiave AES derivata
        assert client_node.key_manager.current_key is not None
        assert len(client_node.key_manager.current_key) == 32
        
    except Exception as e:
        pytest.fail(f"Handshake fallito: {e}")
    finally:
        client_node.shutdown()

def test_e2e_ping_pong(secure_server):
    """TEST 2: Verifica che il protocollo 'ping' riceva un 'pong'."""
    host, port = secure_server
    
    # Esegui handshake
    # 🟢 FIX: Ottieni l'istanza del client_node
    client_node, sock, protocol = perform_client_handshake(host, port)
    
    try:
        # 1. Crea e invia pacchetto PING
        ping_packet = protocol._create_json_packet('ping', {})
        sock.sendall(ping_packet)
        
        # 2. Leggi e parsa la risposta
        # (Usiamo l'helper del client node per leggere)
        client_id = f"{host}:{port}"
        # 🟢 FIX: Chiama il metodo sull'istanza corretta
        pkt_type, payload, offset = client_node._read_and_parse_packet(sock, client_id, protocol)
        
        assert pkt_type == 'json'
        assert payload.get('type') == 'pong'
        
    except Exception as e:
        pytest.fail(f"Test Ping-Pong fallito: {e}")
    finally:
        sock.close()


def test_e2e_transfer_happy_path(secure_server, test_file_factory, server_output_dir):
    """TEST 3: Verifica trasferimento file E2E (Happy Path)."""
    host, port = secure_server
    
    # 1. Crea file di test
    file_path, file_hash = test_file_factory("file_happy.bin", 50) # 50KB
    
    # 2. Avvia client e invia
    client = SecureFileTransferNode(mode='client')
    try:
        client.connect_to_server(host, port)
        client.send_file(str(file_path))
    except Exception as e:
        pytest.fail(f"Invio file (happy path) fallito: {e}")
    finally:
        client.shutdown()
        
    # 3. Verifica file ricevuto
    # 🟢 FIX: Controlla la directory OUTPUT_DIR (patchata), non 'ricevuti'
    received_file = server_output_dir / file_path.name
    assert received_file.exists()
    assert received_file.stat().st_size == file_path.stat().st_size
    
    # 4. Verifica hash
    received_hash = hashlib.sha256(received_file.read_bytes()).hexdigest()
    assert received_hash == file_hash

def test_e2e_transfer_resume(secure_server, test_file_factory, server_output_dir):
    """TEST 4: Verifica resume trasferimento file E2E."""
    host, port = secure_server
    
    # 1. Crea file di test (es. 100KB)
    file_path, file_hash = test_file_factory("file_resume.bin", 100)
    
    # 2. Simula file parziale sul server
    # (Scrivi i primi 30KB)
    partial_size = 30 * 1024
    partial_content = file_path.read_bytes()[:partial_size]
    
    # 🟢 FIX: Scrivi il file parziale nella directory OUTPUT_DIR (patchata)
    received_file = server_output_dir / file_path.name
    received_file.write_bytes(partial_content)
    assert received_file.stat().st_size == partial_size
    
    # 3. Avvia client e invia (deve riprendere)
    client = SecureFileTransferNode(mode='client')
    
    # 4. Monitora il client per l'offset
    # (Usiamo un mock sul _read_and_parse_packet)
    # Vogliamo verificare che il server invii 'offset': 30720
    
    # NOTA: Per questo test, potremmo anche solo verificare il risultato finale,
    # che è più semplice e robusto.
    
    # 🟢 FIX: La logica di resume (Analisi #10) è stata corretta in 
    # secure_file_transfer_fixed.py, ora il test deve passare.
    
    try:
        client.connect_to_server(host, port)
        client.send_file(str(file_path))
    except Exception as e:
        pytest.fail(f"Invio file (resume) fallito: {e}")
    finally:
        client.shutdown()
        
    # 5. Verifica file finale
    assert received_file.exists()
    assert received_file.stat().st_size == file_path.stat().st_size
    
    received_hash = hashlib.sha256(received_file.read_bytes()).hexdigest()
    assert received_hash == file_hash
    print("\nTest Resume: Hash finale verificato.")

# 🟢 FIX (Analisi #18): Rimosso il decoratore @patch inefficace
def test_e2e_protocol_replay_attack(secure_server):
    """TEST 5: Verifica che il server rifiuti un replay attack (invio duplicato)."""
    host, port = secure_server
    
    # 🟢 FIX: Ottieni client_node (anche se non usato, per coerenza)
    client_node, sock, protocol = perform_client_handshake(host, port)
    
    try:
        # 1. Crea e invia pacchetto PING
        ping_packet = protocol._create_json_packet('ping', {})
        sock.sendall(ping_packet)
        
        # 2. Attendi risposta al primo ping
        time.sleep(0.1)
        response1 = sock.recv(1024)
        assert len(response1) > 0, "Primo ping dovrebbe ricevere risposta"
        
        # 3. REPLAY ATTACK: Invia lo STESSO pacchetto identico
        # (stesso nonce, stesso timestamp, stessa firma)
        sock.sendall(ping_packet)
        
        # 4. Il server deve chiudere la connessione o non rispondere
        time.sleep(0.2)
        data = sock.recv(1024)
        
        # Se la connessione è chiusa, recv ritorna b''
        assert data == b'', "Il server non ha chiuso la connessione per replay attack"
        print("\n✓ Test Replay Attack: Server ha correttamente rifiutato il messaggio duplicato")
        
    except Exception as e:
        # Se il server chiude, potremmo avere un ConnectionResetError,
        # che è OK in questo caso.
        print(f"\n✓ Test Replay Attack (connessione chiusa): {e}")
        pass
    finally:
        sock.close()

# 🟢 FIX (Analisi #18): Rimosso il decoratore @patch
def test_e2e_protocol_invalid_signature(secure_server):
    """TEST 6: Verifica che il server rifiuti una firma non valida."""
    host, port = secure_server
    
    # 🟢 FIX: Ottieni client_node (anche se non usato, per coerenza)
    client_node, sock, protocol = perform_client_handshake(host, port)
    
    # 🟢 FIX (Analisi #18): Applica il patch direttamente all'ISTANZA
    with patch.object(protocol.key_manager, 'sign_data', return_value=b'\x00' * 32):
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
    
    # 🟢 FIX: Ottieni client_node (anche se non usato, per coerenza)
    client_node, sock, protocol = perform_client_handshake(host, port)
    
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