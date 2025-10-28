# test_security_protocol.py

import pytest
import socket
import threading
import time
import struct
from pathlib import Path
from collections import deque

# Importiamo i componenti necessari dal nostro script principale
# Assumiamo che i file siano nella stessa directory
from secure_file_transfer_fixed import SecureFileTransferNode, SecureProtocol, SecureKeyManager, HEADER_PACKET_SIZE

# Definiamo costanti per il test
TEST_PORT = 5556
TEST_HOST = '127.0.0.1'

@pytest.fixture(scope="module")
def secure_server():
    """
    Fixture Pytest per avviare il server in un thread separato.
    'scope="module"' assicura che il server giri per tutti i test in questo file.
    """
    server_node = SecureFileTransferNode(mode='server', host=TEST_HOST, port=TEST_PORT)
    
    # Avvia il server in un thread daemon
    server_thread = threading.Thread(target=server_node.start_server, daemon=True)
    server_thread.start()
    
    # Diamo al server un momento per avviarsi
    time.sleep(0.5)
    
    yield (TEST_HOST, TEST_PORT)
    
    # Cleanup: arresta il server dopo che tutti i test sono finiti
    server_node.shutdown()

def perform_client_handshake(host, port) -> Tuple[socket.socket, SecureProtocol]:
    """
    Helper per eseguire un handshake client manuale e restituire 
    un socket connesso e un'istanza di SecureProtocol pronta.
    """
    # 0. Inizializza il KeyManager e il Protocollo lato client
    key_manager = SecureKeyManager('test_client')
    # Usiamo una deque fittizia per il protocollo
    protocol = SecureProtocol(key_manager, deque(maxlen=100))

    # 1. Connessione
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    sock.connect((host, port))
    
    # 2. Esegui l'handshake come definito in _perform_secure_handshake
    try:
        # Invia la chiave pubblica
        public_key_pem = key_manager.get_public_key_pem()
        sock.sendall(struct.pack('!I', len(public_key_pem)) + public_key_pem)

        # Ricevi la chiave pubblica del server
        header = sock.recv(4)
        if not header: raise ConnectionError("Handshake failed: no peer key header")
        peer_key_len, = struct.unpack('!I', header)
        peer_key_pem = sock.recv(peer_key_len)
        if not peer_key_pem: raise ConnectionError("Handshake failed: no peer key")

        # Stabilisci e invia il segreto
        encrypted_secret = key_manager.establish_shared_secret(peer_key_pem)
        sock.sendall(struct.pack('!I', len(encrypted_secret)) + encrypted_secret)
        
        # Ricevi conferma
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

# --- Test Cases ---

def test_nonce_uniqueness(secure_server):
    """
    TEST 1: Verifica che due pacchetti consecutivi sulla stessa connessione
    usino due Nonce diversi.
    """
    host, port = secure_server
    sock, protocol = perform_client_handshake(host, port)
    
    try:
        # Crea e invia il primo pacchetto
        packet1_bytes = protocol.create_packet('ping', {})
        sock.sendall(packet1_bytes)
        
        # Crea e invia il secondo pacchetto
        packet2_bytes = protocol.create_packet('ping', {})
        sock.sendall(packet2_bytes)
        
        # Estrai i nonce dall'header.
        # Basato su struct.pack('!4sII16s12s16s')
        # Offset: magic(4) + version(4) + payload_len(4) + key_id(16) = 28
        # Lunghezza Nonce = 12
        nonce1 = packet1_bytes[28:40]
        nonce2 = packet2_bytes[28:40]
        
        print(f"Nonce 1: {nonce1.hex()}")
        print(f"Nonce 2: {nonce2.hex()}")
        
        assert len(nonce1) == 12
        assert len(nonce2) == 12
        assert nonce1 != nonce2, "I Nonce sono identici! Fallimento catastrofico di AES-GCM."

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
        valid_packet = protocol.create_packet('ping', {})
        sock.sendall(valid_packet)
        
        # Aspetta la risposta PONG per essere sicuri che il server lo abbia processato
        # Dobbiamo leggere l'header + il payload del pong
        header_bytes = sock.recv(HEADER_PACKET_SIZE)
        assert header_bytes, "Il server non ha risposto al primo ping"
        
        # Ora, invia DI NUOVO lo stesso identico pacchetto
        print("Invio pacchetto replay...")
        sock.sendall(valid_packet)
        
        # Il server dovrebbe rilevare il replay
        # e chiudere la connessione.
        # Un 'recv' su un socket chiuso restituirà b''
        
        # Aggiungiamo un piccolo ritardo per dare al server il tempo di chiudere
        time.sleep(0.2) 
        
        data = sock.recv(1024)
        
        assert data == b'', "Il server non ha chiuso la connessione dopo un replay attack"
        print("Il server ha chiuso correttamente la connessione.")

    finally:
        sock.close()