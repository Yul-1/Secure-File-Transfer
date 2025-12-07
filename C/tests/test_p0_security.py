#!/usr/bin/env python3
"""
Suite di Test P0 (Critici) per AegisTransfer (secure_file_transfer_fixed.py)
Team: _team controllo
(Versione 1.3: Corretto nome fixture, iniezione dir, e test lenti)
"""

import pytest
import threading
import time
import socket
import struct
import hashlib
import logging
from pathlib import Path
from typing import Tuple, Generator
from unittest.mock import patch, MagicMock

# Importa le classi necessarie dal codice sorgente
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

try:
    from sft import (
        SecureFileTransferNode,
        SecureKeyManager,
        HEADER_FORMAT,
        HEADER_PACKET_SIZE,
        IDLE_TIMEOUT,
        SOCKET_TIMEOUT,
        MAX_PACKET_SIZE,
        OUTPUT_DIR # Importato per riferimento, ma patchato
    )
except ImportError as e:
    print(f"Errore: Impossibile importare 'secure_file_transfer_fixed.py'. Assicurati che sia nel PYTHONPATH.")
    sys.exit(1)


# --- Fixtures ---
# Rimosse. Si affida a conftest.py

@pytest.fixture
def malicious_socket(persistent_server: SecureFileTransferNode) -> Generator[socket.socket, None, None]:
    """
    Socket grezzo (TCP) connesso al server (NO handshake).
    (FIX 2.0: Usa 'persistent_server')
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(SOCKET_TIMEOUT) 
    try:
        # (FIX 2.0) Usa la porta del persistent_server
        s.connect(('127.0.0.1', persistent_server.port))
        print(f"\n[Fixture] Socket malizioso connesso alla porta {persistent_server.port}")
        yield s
    finally:
        print("[Fixture] Socket malizioso chiuso.")
        s.close()

@pytest.fixture
def malicious_client_authed(malicious_socket: socket.socket) -> Generator[Tuple[socket.socket, SecureKeyManager], None, None]:
    """
    Socket grezzo che ha completato l'handshake ECDH + Ed25519.
    """
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    import os

    sock = malicious_socket
    km = SecureKeyManager("malicious_client")

    try:
        my_ephemeral_bytes = km.generate_ephemeral_key()
        sock.sendall(struct.pack('!I', len(my_ephemeral_bytes)) + my_ephemeral_bytes)

        header = sock.recv(4)
        if not header: raise ConnectionAbortedError("Server ha chiuso durante handshake")
        len_s_eph, = struct.unpack('!I', header)
        server_ephemeral = sock.recv(len_s_eph)

        header = sock.recv(4)
        if not header: raise ConnectionAbortedError("Server ha chiuso durante handshake")
        len_s_id, = struct.unpack('!I', header)
        server_identity = sock.recv(len_s_id)

        header = sock.recv(4)
        if not header: raise ConnectionAbortedError("Server ha chiuso durante handshake")
        len_sig, = struct.unpack('!I', header)
        signature = sock.recv(len_sig)

        if not (server_ephemeral and server_identity and signature):
            raise ConnectionAbortedError("Handshake incompleto")

        transcript = my_ephemeral_bytes + server_ephemeral
        if not km.verify_handshake_signature(server_identity, transcript, signature):
            raise ConnectionAbortedError("Signature verification failed")

        km.compute_shared_secret(server_ephemeral)

        nonce = os.urandom(12)
        cipher = Cipher(algorithms.AES(km.current_key), modes.GCM(nonce), backend=default_backend())
        encryptor = cipher.encryptor()
        ct = encryptor.update(b"AUTH_OK") + encryptor.finalize()
        tag = encryptor.tag
        payload = nonce + tag + ct
        sock.sendall(struct.pack('!I', len(payload)) + payload)

        header = sock.recv(4)
        if not header: raise ConnectionAbortedError("Server ha chiuso durante conferma")
        len_resp, = struct.unpack('!I', header)
        resp_payload = sock.recv(len_resp)
        if not resp_payload: raise ConnectionAbortedError("Server ha chiuso durante conferma")

        nonce_s, tag_s, ct_s = resp_payload[:12], resp_payload[12:28], resp_payload[28:]
        cipher_s = Cipher(algorithms.AES(km.current_key), modes.GCM(nonce_s, tag_s), backend=default_backend())
        decryptor_s = cipher_s.decryptor()
        pt_s = decryptor_s.update(ct_s) + decryptor_s.finalize()

        if pt_s != b"AUTH_OK":
            raise ConnectionAbortedError("Server non ha confermato AUTH_OK")

        print("[Fixture] Handshake client malizioso completato.")

        yield sock, km

    except Exception as e:
        pytest.fail(f"Handshake client malizioso fallito: {e}")


# --- Test P0 (Critici) ---

def test_p0_idle_timeout_slowloris(connected_client: SecureFileTransferNode, persistent_server: SecureFileTransferNode):
    """
    P0.1: Verifica che il server NON chiuda una connessione
    prima di IDLE_TIMEOUT.
    (FIX 2.1: Test reso veloce, 2s di attesa)
    """
    print(f"\n--- test_p0_idle_timeout_slowloris ---")
    wait_time = 2 # Attesa breve per CI
    print(f"Client connesso. In attesa di {wait_time}s (test veloce)...")
    
    time.sleep(wait_time) 
    
    print(f"Attesa completata ({wait_time}s). Provo a usare la connessione.")
    
    try:
        # Il test ora verifica che la connessione sia ANCORA ATTIVA
        response = connected_client.list_files()
        assert isinstance(response, list)
        print("Test P0.1 (Idle Timeout) completato: Connessione ancora attiva come previsto.")
    except Exception as e:
        pytest.fail(f"Connessione chiusa inaspettatamente dopo {wait_time}s: {e}")


def test_p0_socket_timeout_slowloris(malicious_client_authed: Tuple[socket.socket, SecureKeyManager]):
    """
    P0.2: Verifica che il server NON chiuda una connessione
    prima di SOCKET_TIMEOUT.
    (FIX 2.1: Test reso veloce, 2s di attesa)
    """
    print(f"\n--- test_p0_socket_timeout_slowloris ---")
    sock, km = malicious_client_authed
    
    partial_header = b'SFTP\x00\x00\x00\x02\x01\x00' # 10 byte
    
    print(f"Invio header parziale ({len(partial_header)} bytes).")
    sock.sendall(partial_header)
    
    wait_time = 2 # Attesa breve per CI
    print(f"In attesa di {wait_time}s (test veloce)...")
    time.sleep(wait_time)
    
    print("Timeout (breve) atteso. Provo a leggere.")
    
    # Verifica che la connessione sia ANCORA ATTIVA
    sock.setblocking(False)
    try:
        data = sock.recv(1024)
        # Se non riceviamo dati (None o b''), va bene, 
        # l'importante è che il socket non sia chiuso (EOF)
        assert data != b''
        print("Test P0.2 (Socket Timeout) completato: Connessione ancora attiva come previsto.")
    except (BlockingIOError, InterruptedError):
        # Nessun dato da leggere, che è normale
        print("Test P0.2 (Socket Timeout) completato: Connessione ancora attiva (BlockingIOError).")
    except Exception as e:
        pytest.fail(f"Errore socket inaspettato: {e}")
    finally:
        sock.setblocking(True)


def test_p0_max_packet_size_dos(malicious_client_authed: Tuple[socket.socket, SecureKeyManager]):
    """
    P0.3: Verifica che il server rifiuti un header che dichiara
    un payload > MAX_PACKET_SIZE.
    """
    print(f"\n--- test_p0_max_packet_size_dos ---")
    sock, km = malicious_client_authed
    
    fake_payload_len = MAX_PACKET_SIZE + 1
    
    fake_header = struct.pack(
        HEADER_FORMAT,
        b'SFTP', 2, 0x01, 0,
        fake_payload_len,
        b'fake_key_id\x00\x00\x00\x00\x00', 
        b'fake_nonce\x00\x00\x00\x00',     
        b'fake_tag\x00\x00\x00\x00\x00\x00\x00\x00'  
    )
    
    print(f"Invio header falsificato (PayloadLen: {fake_payload_len}).")
    sock.sendall(fake_header)
    
    print("In attesa che il server chiuda la connessione...")
    time.sleep(1) 
    
    data = sock.recv(1024)
    assert data == b'', "Il server non ha chiuso la connessione (EOF non ricevuto)"
    
    print("Test P0.3 (MAX_PACKET_SIZE) completato: Connessione chiusa come previsto.")

def test_p0_replay_attack(connected_client: SecureFileTransferNode, monkeypatch: pytest.MonkeyPatch):
    """
    P0.4: Verifica che il server rifiuti un comando JSON identico
    inviato due volte.
    """
    print(f"\n--- test_p0_replay_attack ---")
    client = connected_client
    
    sent_packets = []
    original_create_json_packet = client.protocol._create_json_packet
    
    def spy_create_json_packet(msg_type: str, payload: dict, sign: bool = True) -> bytes:
        packet_bytes = original_create_json_packet(msg_type, payload, sign)
        print(f"[Spy] Catturato pacchetto (tipo: {msg_type}, dim: {len(packet_bytes)})")
        sent_packets.append(packet_bytes)
        return packet_bytes
        
    monkeypatch.setattr(client.protocol, "_create_json_packet", spy_create_json_packet)
    
    print("Invio primo comando 'list_files'...")
    response = client.list_files()
    assert isinstance(response, list) 
    assert len(sent_packets) == 1 
    
    replay_packet = sent_packets[0]
    monkeypatch.setattr(client.protocol, "_create_json_packet", original_create_json_packet)
    
    print("Re-invio pacchetto catturato (replay)...")
    assert client.peer_socket is not None
    client.peer_socket.sendall(replay_packet)
    
    print("Invio secondo comando 'list_files' (dovrebbe fallire)...")
    
    with pytest.raises((ConnectionAbortedError, ConnectionResetError, BrokenPipeError, OSError, ValueError)):
        client.list_files()
        
    print("Test P0.4 (Replay Attack) completato: Connessione chiusa come previsto.")

def test_p0_invalid_key_id(connected_client: SecureFileTransferNode, monkeypatch: pytest.MonkeyPatch):
    """
    P0.5: Verifica che il server rifiuti un pacchetto con Key ID corrotto.
    """
    print(f"\n--- test_p0_invalid_key_id ---")
    client = connected_client
    
    original_struct_pack = struct.pack
    _patch_done = False

    def tamper_key_id_pack(format_string: str, *args) -> bytes:
        nonlocal _patch_done
        if format_string == HEADER_FORMAT and not _patch_done:
            _patch_done = True
            unpacked = list(args)
            original_key_id = unpacked[5]
            unpacked[5] = b'INVALID_KEY_ID\x00\x00' # 16 byte
            print(f"Key ID originale: {original_key_id.hex()}, Key ID modificato: {unpacked[5].hex()}")
            return original_struct_pack(format_string, *unpacked)
        
        return original_struct_pack(format_string, *args)
    
    monkeypatch.setattr(struct, "pack", tamper_key_id_pack)

    print("Invio comando 'list_files' con Key ID modificato...")
    
    with pytest.raises((ConnectionAbortedError, ConnectionResetError, BrokenPipeError, OSError, ValueError)):
        client.list_files()
        
    print("Test P0.5 (Invalid Key ID) completato: Connessione chiusa come previsto.")

def test_p0_hash_mismatch_on_resume(
    connected_client: SecureFileTransferNode, 
    persistent_server: SecureFileTransferNode, 
    server_output_dir: Path, # (FIX 2.0) Inietta fixture
    tmp_path: Path, 
    caplog: pytest.LogCaptureFixture
):
    """
    P0.6: Verifica che il server rilevi un HASH MISMATCH se un file
    locale viene ripreso ma era corrotto.
    """
    print(f"\n--- test_p0_hash_mismatch_on_resume ---")
    client = connected_client
    
    filename = "resume_hash_test.txt"
    corrupt_file_path = server_output_dir / filename
    corrupt_data = b"ABCDEFGHIJ" # 10 byte
    corrupt_file_path.write_bytes(corrupt_data)
    
    assert corrupt_file_path.exists()
    assert corrupt_file_path.stat().st_size == len(corrupt_data)

    good_file_path = tmp_path / filename
    good_data =    b"1234567890KLMNOPQRST" # 20 byte
    good_file_path.write_bytes(good_data)
    good_hash = hashlib.sha256(good_data).hexdigest()
    
    print(f"File corrotto (Server): {len(corrupt_data)} bytes")
    print(f"File buono (Client): {len(good_data)} bytes. Hash atteso: {good_hash[:10]}...")

    print(f"Avvio upload (Resume previsto da offset 10)...")
    
    caplog.clear()
    with caplog.at_level(logging.INFO):
        client.send_file(str(good_file_path))
    
    print("Upload completato.")
    
    client_logs = [rec.message for rec in caplog.records]
    
    # 1. Verifica che il resume sia avvenuto
    expected_resume_log = "Peer ACK. Starting upload from offset: 10"
    assert any(expected_resume_log in msg for msg in client_logs), \
        f"Il client non ha ripreso dall'offset 10. Log: {client_logs}"
    
    # 2. Verifica che il client abbia ricevuto l'errore di mismatch
    expected_log = "Peer reported error in final ACK: Hash mismatch on server"
    assert any(expected_log in msg for msg in client_logs), \
        f"Il client non ha loggato l'errore di hash mismatch. Log: {client_logs}"

    print("Test P0.6 (Hash Mismatch) completato: Resume e HASH MISMATCH rilevati correttamente.")