import pytest
import threading
import time
import socket
from pathlib import Path
import os
import sys
# 🟢 FIX: Importa MonkeyPatch per l'uso session-scoped
from _pytest.monkeypatch import MonkeyPatch

# Aggiungi la root del progetto al path per importare i moduli
sys.path.insert(0, str(Path(__file__).parent.parent))

# Importa solo dopo aver modificato il path
from sft import SecureFileTransferNode, OUTPUT_DIR, DEFAULT_PORT

# --- Fixture di Sessione (per server e file) ---

@pytest.fixture(scope="session")
def server_output_dir(tmp_path_factory):
    """Crea una directory di output temporanea per i file del server.
    
    🟢 FIX (Analisi #17): Monkeypatch Pattern Robusto
    
    PROBLEMA:
    `monkeypatch.setattr('module.VARIABLE', value)` (string-based) 
    NON funziona se un modulo ha già fatto `from module import VARIABLE`.
    
    SOLUZIONE IMPLEMENTATA:
    1. Importiamo il MODULO direttamente: `import secure_file_transfer_fixed`
    2. Patchiamo l'attributo del modulo: `mp.setattr(module, 'ATTR', value)`
    3. I test importano DOPO che conftest ha applicato il patch
    
    Questo funziona perché:
    - conftest.py viene caricato PRIMA dei test
    - Il patch modifica l'attributo del modulo PRIMA che i test lo importino
    - `from secure_file_transfer_fixed import OUTPUT_DIR` ottiene il valore patchato
    
    Pattern da EVITARE:
    ❌ mp.setattr('secure_file_transfer_fixed.OUTPUT_DIR', value)  # String-based
    
    Pattern CORRETTO:
    ✅ import module; mp.setattr(module, 'OUTPUT_DIR', value)  # Object-based
    """
    server_output_dir = tmp_path_factory.mktemp("server_files")
    
    # Non possiamo richiedere 'monkeypatch' (function scope)
    # in una fixture 'session' scope.
    # Creiamo manualmente un MonkeyPatch session-scoped.
    mp = MonkeyPatch()
    
    import sft
    # Applica il patch (object-based, non string-based)
    mp.setattr(sft, 'OUTPUT_DIR', server_output_dir)
    
    yield server_output_dir
    
    # Pulisci il patch
    mp.undo()


@pytest.fixture(scope="session")
def dummy_file_factory(tmp_path_factory):
    """Factory per creare file di test fittizi."""
    
    def _create_file(filename: str, size_kb: int) -> Path:
        # Crea i file in una directory temporanea di sessione
        # (tmp_path_factory è necessario per lo scope "session")
        file_dir = tmp_path_factory.mktemp("dummy_files_src")
        file_path = file_dir / filename
        file_path.write_bytes(os.urandom(size_kb * 1024))
        return file_path

    return _create_file

# --- Fixture per Server (scope=module) ---
# Usato da test_security_protocol e test_concurrency

@pytest.fixture(scope="module")
def persistent_server(server_output_dir):
    """
    Avvia un server che dura per l'intera sessione di test (modulo).
    Usa la directory di output temporanea (patchata da server_output_dir).
    """
    
    # Chiedi al SO una porta libera (porta 0)
    server = SecureFileTransferNode(mode='server', host='127.0.0.1', port=0)
    
    server_thread = threading.Thread(target=server.start_server, daemon=True)
    server_thread.start()
    
    # Attesa robusta per l'avvio e l'assegnazione della porta
    start_time = time.time()
    while not server.running or server.port == 0:
        time.sleep(0.01)
        if time.time() - start_time > 10.0: # Timeout 10 secondi
            pytest.fail("Server persistente non avviato entro 10s.")
            
    print(f"\n--- Server (persistent) avviato su porta {server.port} ---")
    
    yield server
    
    # Teardown
    print("\n--- Shutdown server (persistent) ---")
    server.shutdown()
    server_thread.join(timeout=2.0)

# --- Fixture per Client (scope=function) ---
# Usato da test_security_protocol e test_concurrency

@pytest.fixture(scope="function")
def connected_client(persistent_server):
    """
    Fornisce un client GIA' CONNESSO E AUTENTICATO
    per un singolo test. Si pulisce da solo.
    """
    client = SecureFileTransferNode(mode='client')
    try:
        # Connettiti al server del modulo (che ha una porta fissa)
        client.connect_to_server('127.0.0.1', persistent_server.port)
    except Exception as e:
        pytest.fail(f"Fixture connected_client non riuscita a connettersi: {e}")
        
    yield client
    
    # Teardown (chiudi il client dopo ogni test)
    client.shutdown()