import pytest
import threading
import socket
import time
import logging
import os
from pathlib import Path
# 🟢 CORREZIONE: Assicurati che il file del server sia trovato
# Aggiungiamo la root del progetto al path per gli import
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

# 🟢 FIX: Importa OUTPUT_DIR (che sarà patchato da conftest)
from secure_file_transfer_fixed import SecureFileTransferNode, DEFAULT_PORT, OUTPUT_DIR

# --- Fixture per il Server e il File di Test ---

@pytest.fixture(scope="function")
def running_server(server_output_dir):
    """Avvia il server in un thread separato per ogni test."""
    
    # 🟢 MODIFICA: Chiedi al SO una porta libera (porta 0)
    server = SecureFileTransferNode(mode='server', host='127.0.0.1', port=0)
    
    server_thread = threading.Thread(target=server.start_server, daemon=True)
    server_thread.start()
    
    # 🟢 FIX (Analisi #14): Sostituisce sleep(0.5) con attesa attiva
    start_time = time.time()
    while not server.running or server.port == 0:
        time.sleep(0.01)
        if time.time() - start_time > 5.0: # Timeout 5 secondi
            pytest.fail("Il server non è riuscito ad avviarsi entro 5 secondi.")
    
    # 🟢 MODIFICA: Assicurati che il server sia partito e abbia una porta
    if not server.running or server.port == 0:
        pytest.fail("Il server non è riuscito ad avviarsi o ottenere una porta.")

    yield server
    
    # Teardown
    server.shutdown()
    server_thread.join(timeout=1.0)
    # Pulisci i file ricevuti per evitare interferenze
    # 🟢 FIX: Pulisci la directory corretta (patchata)
    for f in OUTPUT_DIR.glob("*"):
        try:
            os.remove(f)
        except OSError:
            pass # Ignora se i file sono bloccati (Windows) o già rimossi

@pytest.fixture(scope="session")
def test_file(tmp_path_factory):
    """Crea un file di test fittizio per la sessione."""
    file_path = tmp_path_factory.mktemp("test_files") / "file_10k.bin"
    file_path.write_bytes(b'\xAA' * (10 * 1024)) # 10KB
    return file_path

# --- Funzione Helper per Attacco ---

def attacker_connect(host, port, results_list):
    """Tenta una singola connessione e registra il successo/fallimento."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2.0)
        sock.connect((host, port))
        # Se arriva qui, la connessione è riuscita (non bloccata dal rate limit)
        results_list.append("SUCCESS")
        sock.close()
    except (socket.timeout, ConnectionRefusedError, ConnectionResetError) as e:
        # Connessione fallita (bloccata o server chiuso)
        results_list.append(f"FAILED: {type(e).__name__}")
    except Exception as e:
        results_list.append(f"ERROR: {e}")

# --- Test Suite DoS ---

def test_rate_limit_single_ip(running_server, caplog):
    """
    Testa se il RateLimiter (pre-handshake) blocca
    correttamente un IP dopo aver superato il limite.
    """
    caplog.set_level(logging.INFO)
    
    # 🟢 MODIFICA: Usa la porta dinamica
    host, port = '127.0.0.1', running_server.port
    
    # Il limite pre-handshake è 10 (definito in SecureFileTransferNode)
    limit = 10 
    num_attempts = 15
    results = []
    
    print(f"\n[TEST] Esecuzione {num_attempts} connessioni veloci da 1 IP a porta {port}...")

    threads = []
    for _ in range(num_attempts):
        t = threading.Thread(target=attacker_connect, args=(host, port, results))
        t.start()
        threads.append(t)
        time.sleep(0.01) # Staggering leggero

    for t in threads:
        t.join(timeout=3.0)
    
    # 🟢 FIX (Analisi #13): Sleep per permettere flush log
    # Con 15 thread concorrenti che scrivono log, caplog potrebbe
    # non catturare tutti i messaggi istantaneamente. Diamo tempo
    # al logging handler di fare flush.
    time.sleep(0.15)

    # Verifica i log per il rate limiting
    log_messages = [record.message for record in caplog.records 
                    if "Connection rate limit (pre-handshake) exceeded" in record.message]
    
    print(f"[RISULTATO] Log 'Rate Limit' catturati: {len(log_messages)}")
    
    # Verifica che (num_attempts - limit) connessioni siano state bloccate
    # Diamo un po' di tolleranza (>=)
    expected_failures = num_attempts - limit
    assert len(log_messages) >= expected_failures 

def test_rate_limit_multiple_ips(running_server, caplog):
    """
    Testa che il RateLimiter permetta a IP diversi di
    connettersi, anche se un IP è bloccato.
    (Simuliamo IP diversi usando '127.0.0.2', ecc.)
    """
    caplog.set_level(logging.INFO)
    
    # 🟢 MODIFICA: Usa la porta dinamica
    host_attacker = '127.0.0.1' # Questo IP attaccherà
    host_legit = '127.0.0.2'   # Questo IP deve passare
    port = running_server.port
    limit = 10
    num_attempts = 15
    
    print(f"\n[TEST] Esecuzione {num_attempts} connessioni (attacco) + 1 (legittima) a porta {port}...")
    
    threads = []
    results_attacker = []
    results_legit = []

    # 1. Avvia l'attacco
    for i in range(num_attempts):
        t = threading.Thread(target=attacker_connect, args=(host_attacker, port, results_attacker))
        t.start()
        threads.append(t)
        time.sleep(0.05) # Attesa per assicurare che il rate limit scatti

    # 2. Tenta la connessione legittima
    # (Il server usa 'host' come ID, quindi '127.0.0.2' è un client diverso)
    t_legit = threading.Thread(target=attacker_connect, args=(host_legit, port, results_legit))
    t_legit.start()
    threads.append(t_legit)

    for t in threads:
        t.join(timeout=3.0)

    # 🟢 FIX (Analisi #13): Breve attesa per permettere a caplog
    # di catturare i log dai thread concorrenti.
    time.sleep(0.1)

    # Immediatamente controlla i log
    log_messages = [record.message for record in caplog.records]
    
    incoming_logs = [m for m in log_messages if "Incoming connection attempt" in m]
    rate_limit_logs = [m for m in log_messages if "Connection rate limit (pre-handshake) exceeded" in m]

    print(f"\n[RISULTATO] Log 'Incoming' catturati: {len(incoming_logs)}")
    print(f"[RISULTATO] Log 'Rate Limit' catturati: {len(rate_limit_logs)}")

    # Asserzione 1: Il server deve aver registrato TUTTI i tentativi
    # 🟢 FIX: Il client 'legittimo' (t_legit) fallisce a connettersi
    # a 127.0.0.2 (non in ascolto), quindi non viene loggato.
    assert len(incoming_logs) == num_attempts
    
    # Asserzione 2: Il server deve aver RIFIUTATO (num_attempts - limit) connessioni
    assert len(rate_limit_logs) == num_attempts - limit

def test_legitimate_client_works(running_server, test_file, server_output_dir):
    """
    Testa che un client legittimo possa connettersi 
    e trasferire un file.
    Grazie a scope="function", questo server è "pulito".
    """
    client = SecureFileTransferNode(mode='client')
    
    # 🟢 MODIFICA: Usa la porta dinamica assegnata dalla fixture
    connect_port = running_server.port
    print(f"\n[TEST] Client legittimo si connette a 127.0.0.1:{connect_port}...")

    try:
        client.connect_to_server('127.0.0.1', connect_port)
        client.send_file(str(test_file))
    except Exception as e:
        pytest.fail(f"Il client legittimo non è riuscito a connettersi o trasferire: {e}")
    finally:
        # Assicurati che il client si chiuda anche in caso di fallimento
        client.shutdown()

    # Verifica che il file sia stato ricevuto
    # 🟢 FIX: Controlla la directory OUTPUT_DIR (patchata), non 'ricevuti'
    received_file = server_output_dir / test_file.name
    assert received_file.exists()
    assert received_file.stat().st_size == test_file.stat().st_size
    assert received_file.read_bytes() == test_file.read_bytes()