# conftest.py
import pytest
import threading
import time
from pathlib import Path

# Importiamo la classe principale dal tuo script
from secure_file_transfer_fixed import SecureFileTransferNode, OUTPUT_DIR

@pytest.fixture(scope="function")
def server(monkeypatch, tmp_path):
    """
    Fixture Pytest per avviare e fermare il server in un thread.
    
    - 'monkeypatch' è usato per sovrascrivere la OUTPUT_DIR.
    - 'tmp_path' crea una directory temporanea per i file ricevuti.
    """
    
    # 1. Definiamo un percorso di output temporaneo per questo test
    server_output_dir = tmp_path / "server_output"
    server_output_dir.mkdir()
    
    # 2. Usiamo monkeypatch per cambiare la costante globale SOLO per questo test
    # Questo reindirizza la OUTPUT_DIR
    monkeypatch.setattr('secure_file_transfer_fixed.OUTPUT_DIR', server_output_dir)

    # 3. Configuriamo il server per usare una porta casuale (port=0)
    server_node = SecureFileTransferNode(
        mode='server',
        host='127.0.0.1',
        port=0  # Chiedi al SO una porta libera
    )
    
    # 4. Avviamo il server in un thread separato
    server_thread = threading.Thread(
        target=server_node.start_server,
        daemon=True # Muore se il processo pytest muore
    )
    server_thread.start()
    
    # 5. Attendiamo che il server sia effettivamente avviato e abbia una porta
    # start_server aggiorna server_node.port
    timeout = time.time() + 10  # 10 secondi di timeout
    while server_node.port == 0 and time.time() < timeout:
        time.sleep(0.01)
        
    if server_node.port == 0:
        raise TimeoutError("Server non avviato entro il timeout")

    # 6. Forniamo il nodo server al test
    yield server_node
    
    # 7. Pulizia: spegniamo il server dopo che il test è finito
    server_node.shutdown()
    server_thread.join(timeout=2)