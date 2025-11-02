#!/usr/bin/env python3
"""
Suite di Test P2 (Completezza) per AegisTransfer
Team: _team controllo
(Versione 1.2: Iniezione 'server_output_dir')
(Versione 1.3: Fix Deadlock in P2.2)
"""

import pytest
import threading
import time
import socket
import logging
import os
import signal
import hashlib
import subprocess
import sys
from pathlib import Path
from typing import Tuple, Generator, List, Any

# Importa le classi necessarie dal codice sorgente
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

try:
    from secure_file_transfer_fixed import (
        SecureFileTransferNode,
        OUTPUT_DIR,
        DEFAULT_PORT
    )
except ImportError as e:
    print(f"Errore: Impossibile importare 'secure_file_transfer_fixed.py'. Assicurati che sia nel PYTHONPATH.")
    print(f"Dettagli: {e}")
    sys.exit(1)

# Utility per calcolare l'hash
def sha256_file(file_path: Path) -> str:
    h = hashlib.sha256()
    with file_path.open('rb') as f:
        while chunk := f.read(8192):
            h.update(chunk)
    return h.hexdigest()

# --- Fixtures ---
# Rimosse. Si affida a conftest.py


# --- Test P2 (Completezza) ---

def test_p2_full_bidirectional_transfer(
    connected_client: SecureFileTransferNode, 
    tmp_path: Path,
    server_output_dir: Path # (FIX 2.0) Inietta fixture
):
    """
    P2.1: Verifica che un client possa (1) caricare un file e (2) scaricare
    un file diverso nella stessa sessione.
    (FIX 2.0: Usa 'server_output_dir')
    """
    print(f"\n--- test_p2_full_bidirectional_transfer ---")
    client = connected_client
    
    # --- FASE 1: UPLOAD (Client -> Server) ---
    
    upload_file_path = tmp_path / "upload_test.txt"
    upload_data = os.urandom(1024) * 5 # 5KB
    upload_file_path.write_bytes(upload_data)
    upload_hash = sha256_file(upload_file_path)
    
    print(f"Fase 1: Upload di {upload_file_path.name} ({len(upload_data)} bytes)...")
    
    client.send_file(str(upload_file_path))
    
    # 3. Verifica Upload (sul server)
    server_upload_path = server_output_dir / upload_file_path.name
    assert server_upload_path.exists(), f"Il file di upload non esiste sul server ({server_upload_path})"
    assert server_upload_path.stat().st_size == len(upload_data)
    server_upload_hash = sha256_file(server_upload_path)
    assert server_upload_hash == upload_hash, "Hash mismatch sul file caricato (upload)"
    
    print("Fase 1 (Upload) completata e verificata.")

    # --- FASE 2: DOWNLOAD (Server -> Client) ---

    download_file_name = "download_test.bin"
    server_download_path = server_output_dir / download_file_name
    download_data = os.urandom(1024) * 10 # 10KB
    server_download_path.write_bytes(download_data)
    download_hash = sha256_file(server_download_path)
    
    client_download_path = tmp_path / "received_download.bin"
    
    print(f"Fase 2: Download di {download_file_name} ({len(download_data)} bytes)...")
    
    client.download_file(download_file_name, client_download_path)
    
    assert client_download_path.exists(), "Il file scaricato non esiste sul client"
    assert client_download_path.stat().st_size == len(download_data)
    client_download_hash = sha256_file(client_download_path)
    assert client_download_hash == download_hash, "Hash mismatch sul file scaricato (download)"
    
    print("Fase 2 (Download) completata e verificata.")
    print("Test P2.1 (Bidirezionalità) completato: Trasferimenti riusciti in entrambe le direzioni.")

    # Pulizia
    server_upload_path.unlink()
    server_download_path.unlink()

def test_p2_os_signal_handling(capfd: pytest.CaptureFixture):
    """
    P2.2: Verifica che il server si spenga correttamente
    (graceful shutdown) ricevendo un segnale SIGINT (Ctrl+C).
    (FIX 1.3: Corretto deadlock su stdout/stderr)
    """
    print(f"\n--- test_p2_os_signal_handling ---")
    
    script_path = Path(sys.modules['secure_file_transfer_fixed'].__file__).resolve()
    assert script_path.exists(), "Impossibile trovare lo script secure_file_transfer_fixed.py"

    test_port = DEFAULT_PORT + 10
    
    print(f"Avvio processo server su porta {test_port}...")
    server_process = subprocess.Popen(
        [sys.executable, str(script_path), '--mode', 'server', '--port', str(test_port)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        # Aggiunto 'bufsize=1' per line buffering, aiuta a ottenere output prima
        bufsize=1, 
        creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if sys.platform == "win32" else 0
    )
    
    try:
        timeout = time.time() + 5
        server_ready = False

        # --- INIZIO BLOCCO CORRETTO ---
        # Leggiamo SOLO da stderr, dove ci aspettiamo i log.
        # Questo evita il deadlock della lettura sequenziale bloccante
        # di stderr e stdout.
        
        print("In attesa del server (max 5s)...")
        while time.time() < timeout:
            # NOTA: readline() è ancora bloccante, ma ora è l'unica
            # chiamata.
            line = server_process.stderr.readline() 

            if "Server listening on" in line:
                print("Server rilevato in ascolto (stderr).")
                server_ready = True
                break

            # Se 'line' è vuota E il processo ha un codice di uscita (poll() != None),
            # significa che il server è morto prematuramente (crash).
            if line == '' and server_process.poll() is not None:
                print("Server terminato inaspettatamente durante l'avvio.")
                break
            
            # Piccolo sleep per evitare spin-loop se il processo muore
            # e readline() restituisce '' continuamente.
            time.sleep(0.01) 
        
        # --- FINE BLOCCO CORRETTO ---
            
        assert server_ready, "Il server non è partito entro il timeout (o è crashato)"
        
        print("Invio segnale SIGINT (Ctrl+C)...")
        if sys.platform == "win32":
            server_process.send_signal(signal.CTRL_C_EVENT)
        else:
            server_process.send_signal(signal.SIGINT)
            
        # Attendi che il processo termini dopo il segnale
        # Diamo 5s per lo shutdown graceful
        try:
            stdout, stderr = server_process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            print("Server non ha terminato entro 5s dal SIGINT. Terminazione forzata.")
            server_process.kill()
            stdout, stderr = server_process.communicate()
            assert False, "Shutdown graceful fallito (timeout)"

        
        print("\n--- Output Server (stderr) ---")
        print(stderr)
        print("------------------------------")
        
        assert "User interrupt, shutting down." in stderr, \
            "Log 'User interrupt' non trovato. L'handler SIGINT non è stato eseguito."
            
        assert "Node shut down." in stderr, \
            "Log 'Node shut down.' non trovato. Lo shutdown non è stato completato."
            
        print("Test P2.2 (Gestione Segnali OS) completato: Shutdown graceful verificato.")

    finally:
        # Assicurati che il processo sia morto in ogni caso
        if server_process.poll() is None:
            print("Processo server ancora attivo (finally). Terminazione forzata.")
            server_process.terminate()
            server_process.wait(2)
            server_process.kill()