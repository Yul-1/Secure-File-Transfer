#!/usr/bin/env python3
"""
Test Suite specifica per la validazione della migrazione a ECDH (X25519) + Ed25519.
Verifica la correttezza crittografica, l'handshake e la mitigazione DoS (performance).
"""

import pytest
import threading
import time
import socket
import sys
import os
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import x25519, ed25519

# --- Configurazione Path ---
try:
    project_root = Path(__file__).parent.parent
    sys.path.insert(0, str(project_root))
    
    from sft import (
        SecureFileTransferNode, 
        SecureKeyManager, 
        SecureProtocol,
        OUTPUT_DIR
    )
except ImportError as e:
    print(f"Errore di import: {e}")
    sys.exit(1)

# --- Fixtures ---

@pytest.fixture
def key_managers():
    """Ritorna una coppia di KeyManager (Server e Client) per test unitari."""
    # Server ha una chiave identità fissa
    server_id_key = ed25519.Ed25519PrivateKey.generate()
    server_km = SecureKeyManager("server", identity_key=server_id_key)
    
    # Client ne genera una al volo
    client_km = SecureKeyManager("client")
    
    return server_km, client_km

# --- Test Suite ---

def test_key_manager_crypto_primitives(key_managers):
    """
    Verifica che le primitive crittografiche siano corrette (Curve Ellittiche).
    """
    server_km, client_km = key_managers
    
    # 1. Verifica Tipi Chiave Identità (Deve essere Ed25519, non RSA)
    assert isinstance(server_km.identity_private, ed25519.Ed25519PrivateKey), \
        "La chiave privata del server deve essere Ed25519"
    assert isinstance(client_km.identity_private, ed25519.Ed25519PrivateKey), \
        "La chiave privata del client deve essere Ed25519"
        
    # 2. Verifica Generazione Chiave Effimera (Deve essere X25519)
    # X25519 raw public keys sono sempre 32 bytes
    ephemeral_pub_bytes = server_km.generate_ephemeral_key()
    assert len(ephemeral_pub_bytes) == 32, "Chiave pubblica X25519 deve essere 32 bytes"
    assert isinstance(server_km.ephemeral_private, x25519.X25519PrivateKey), \
        "La chiave effimera privata deve essere X25519"

    print("\n[OK] Primitive crittografiche corrette (Ed25519 + X25519)")

def test_manual_handshake_logic(key_managers):
    """
    Simula la logica matematica dell'handshake senza socket per verificare
    la derivazione del segreto condiviso.
    """
    server_km, client_km = key_managers
    
    # A. Generazione Effimere
    server_eph_pub = server_km.generate_ephemeral_key()
    client_eph_pub = client_km.generate_ephemeral_key()
    
    # B. Firma del Server (Server firma: Client_Eph + Server_Eph)
    transcript = client_eph_pub + server_eph_pub
    signature = server_km.sign_handshake_data(transcript)
    
    # C. Verifica Firma lato Client
    server_id_pub = server_km.get_identity_public_bytes()
    is_valid = client_km.verify_handshake_signature(server_id_pub, transcript, signature)
    assert is_valid is True, "La verifica della firma Ed25519 è fallita"
    
    # D. Derivazione Segreto Condiviso
    # Il server usa la pub del client
    server_km.compute_shared_secret(client_eph_pub)
    # Il client usa la pub del server
    client_km.compute_shared_secret(server_eph_pub)
    
    # E. Verifica Uguaglianza Segreti
    assert server_km.shared_secret is not None
    assert client_km.shared_secret is not None
    assert server_km.shared_secret == client_km.shared_secret, \
        "I segreti condivisi derivati non corrispondono!"
    
    # Verifica che anche le chiavi di sessione (AES) derivate siano uguali
    assert server_km.current_key == client_km.current_key
    
    print("\n[OK] Logica Handshake Manuale verificata: Segreti corrispondono.")

def test_ecdh_handshake_e2e(tmp_path, server_output_dir):
    """
    Test End-to-End: Avvia un server reale e connette un client reale.
    Verifica che l'handshake avvenga e i dati possano essere trasferiti.
    """
    # 1. Avvia Server
    server = SecureFileTransferNode(mode='server', host='127.0.0.1', port=0)
    server_thread = threading.Thread(target=server.start_server, daemon=True)
    server_thread.start()
    
    # Attesa avvio
    timeout = 5
    start = time.time()
    while server.port == 0:
        time.sleep(0.01)
        if time.time() - start > timeout:
            pytest.fail("Server non avviato")
            
    print(f"\nServer avviato su porta {server.port}")
    
    client = SecureFileTransferNode(mode='client')
    try:
        # 2. Connessione e Handshake (Automatico in connect_to_server)
        client.connect_to_server('127.0.0.1', server.port)
        
        # Se siamo qui, l'handshake è riuscito (altrimenti connect solleva eccezione)
        assert client.key_manager.shared_secret is not None
        
        # 3. Test Trasferimento File (per confermare che la chiave AES è corretta)
        secret_content = b"Dati protetti da ECDH e Ed25519"
        test_file = tmp_path / "ecdh_test.txt"
        test_file.write_bytes(secret_content)
        
        client.send_file(str(test_file))
        
        # Verifica ricezione
        received_file = server_output_dir / "ecdh_test.txt"
        assert received_file.exists()
        assert received_file.read_bytes() == secret_content
        
        print("\n[OK] Handshake E2E e trasferimento file riusciti.")
        
    except Exception as e:
        pytest.fail(f"Test E2E fallito: {e}")
    finally:
        client.shutdown()
        server.shutdown()
        server_thread.join(1)

def test_key_generation_performance():
    """
    Verifica che l'istanziazione del KeyManager sia veloce (Mitigazione DoS).
    RSA 4096 richiedeva ~0.5s - 1.0s. 
    Ed25519/X25519 dovrebbe richiedere < 0.01s.
    """
    start_time = time.perf_counter()
    
    # Simuliamo 50 connessioni simultanee (instanziazioni)
    for _ in range(50):
        # Nel nuovo codice, il server passa la chiave identità, quindi è solo copy
        # Ma anche generarla da zero (caso client) deve essere veloce
        km = SecureKeyManager("test_perf") 
        _ = km.generate_ephemeral_key()
        
    end_time = time.perf_counter()
    duration = end_time - start_time
    
    print(f"\nTempo per 50 generazioni chiavi (Curve Ellittiche): {duration:.4f}s")
    
    # Se ci mette più di 1 secondo per 50 chiavi, qualcosa non va (o è tornato RSA)
    assert duration < 1.0, f"Generazione chiavi troppo lenta ({duration}s)! Rischio DoS ancora presente."
    print("[OK] Performance check superato (Mitigazione DoS confermata).")

if __name__ == "__main__":
    # Permette di eseguire il test direttamente con python3
    sys.exit(pytest.main(["-v", __file__]))