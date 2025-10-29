# tests/test_concurrency.py
import pytest
import threading
import time
from pathlib import Path
import hashlib

# 🟢 MODIFICA 1: Cambiamo l'import
# Rimuoviamo l'import diretto di OUTPUT_DIR
from secure_file_transfer_fixed import SecureFileTransferNode
# Importiamo il modulo stesso per accedere alle variabili patchate
import secure_file_transfer_fixed

# Numero di client da simulare
NUM_CONCURRENT_CLIENTS = 5

def run_client_transfer(host: str, port: int, file_path: Path) -> bool:
    """
    Funzione helper eseguita in un thread per simulare un singolo client.
    Restituisce True in caso di successo, altrimenti solleva un'eccezione.
    """
    client_node = None
    try:
        client_node = SecureFileTransferNode(mode='client')
        
        # Connessione e handshake
        client_node.connect_to_server(host, port)
        
        # Invio file
        client_node.send_file(str(file_path))
        
        return True
    except Exception as e:
        print(f"ERRORE CLIENT ({file_path.name}): {e}")
        return False
    finally:
        if client_node:
            client_node.shutdown()

def create_test_file(path: Path, size_kb: int) -> bytes:
    """Crea un file di test con contenuto deterministico."""
    content = (f"file_content_for_{path.name}" * (size_kb * 10)).encode('utf-8')
    content = content[:size_kb * 1024] # Tronca alla dimensione esatta
    path.write_bytes(content)
    return content

@pytest.fixture(scope="function")
def client_test_files(tmp_path) -> dict:
    """
    Fixture per creare i file che i client invieranno.
    Usa una sottodirectory separata di tmp_path.
    """
    client_dir = tmp_path / "client_files"
    client_dir.mkdir()
    
    files = {}
    for i in range(NUM_CONCURRENT_CLIENTS):
        filename = f"test_file_{i}.bin"
        # Usiamo dimensioni diverse per testare scenari misti
        size_kb = (i + 1) * 20 
        file_path = client_dir / filename
        content = create_test_file(file_path, size_kb)
        
        # Calcoliamo l'hash per la verifica
        files[filename] = {
            'path': file_path,
            'hash': hashlib.sha256(content).hexdigest()
        }
    return files


### INIZIO TEST ###

def test_server_fixture(server):
    """Test 'fumo' (smoke test): il server si avvia correttamente?"""
    assert server.running is True
    assert server.port > 1024 # Assicura che una porta sia stata assegnata
    # 🟢 MODIFICA 2: Usiamo la variabile patchata
    assert secure_file_transfer_fixed.OUTPUT_DIR.is_dir()

def test_single_client_transfer(server, client_test_files):
    """Test di base: un singolo client riesce a trasferire un file?"""
    
    # Prendiamo solo il primo file
    file_info = client_test_files['test_file_0.bin']
    file_path = file_info['path']
    
    # Esegui il client (nel thread principale)
    success = run_client_transfer(server.host, server.port, file_path)
    assert success is True
    
    # Verifica (lato server)
    # 🟢 MODIFICA 3: Usiamo la variabile patchata
    received_file = secure_file_transfer_fixed.OUTPUT_DIR / file_path.name
    assert received_file.exists()
    
    # Verifica integrità
    received_hash = hashlib.sha256(received_file.read_bytes()).hexdigest()
    assert received_hash == file_info['hash']

def test_concurrent_client_transfers(server, client_test_files):
    """
    TEST PRINCIPALE:
    Verifica che 5 client possano connettersi e trasferire file 
    contemporaneamente senza errori (race condition).
    """
    threads = []
    
    # 1. Avvia tutti i thread client in rapida successione
    for filename, info in client_test_files.items():
        thread = threading.Thread(
            target=run_client_transfer,
            args=(server.host, server.port, info['path'])
        )
        threads.append(thread)
        thread.start()
        
    # 2. Attendi il completamento di tutti i trasferimenti
    for thread in threads:
        thread.join(timeout=30) # 30 secondi di timeout per thread
        
    # 3. Verifica i risultati (lato server)
    # Questa è la verifica cruciale: tutti i file sono arrivati intatti?
    
    for filename, info in client_test_files.items():
        # 🟢 MODIFICA 4: Usiamo la variabile patchata
        received_file = secure_file_transfer_fixed.OUTPUT_DIR / filename
        
        # 3.1. Il file esiste?
        assert received_file.exists(), f"File {filename} non ricevuto dal server"
        
        # 3.2. L'integrità è corretta?
        received_hash = hashlib.sha256(received_file.read_bytes()).hexdigest()
        assert received_hash == info['hash'], f"Integrità file {filename} compromessa"