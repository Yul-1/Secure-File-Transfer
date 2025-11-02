#!/usr/bin/env python3
"""
Sistema di Trasferimento File Cifrato con Sicurezza Rafforzata
Versione corretta con tutte le vulnerabilitÃ  risolte
(Refactoring v2.5: Thread-safe state-per-thread)
(Refactoring v2.6: Aggiunta BidirezionalitÃ )
"""

import socket
import os
import hashlib
import hmac
import secrets
import struct
import json
import threading
import time
import argparse
import re
import logging
import ipaddress
import select
from pathlib import Path
from typing import Tuple, Optional, Dict, Any, Set
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding as sym_padding
from datetime import datetime, timedelta, timezone
from collections import deque
from jsonschema import validate, ValidationError

# Configurazione sicurezza
BUFFER_SIZE = 4096  # Dimensione chunk per lettura file
KEY_ROTATION_INTERVAL = 300
MAX_FILE_SIZE = 10 * 1024 * 1024 * 1024 # Aumentato a 10GB (gestito da chunking)
PROTOCOL_VERSION = "2.0"
DEFAULT_PORT = 5555
MAX_PACKET_SIZE = 10 * 1024 * 1024  # 10MB max per pacchetto (JSON o Data chunk)
SOCKET_TIMEOUT = 30
MAX_FAILED_ATTEMPTS = 5
RATE_LIMIT_WINDOW = 60  # secondi
MAX_REQUESTS_PER_WINDOW = 100
MAX_RECEIVED_MESSAGES = 1000
MAX_GLOBAL_CONNECTIONS = 50
IDLE_TIMEOUT = 60 # Secondi di inattivitÃ  prima di chiudere
OUTPUT_DIR = Path("ricevuti")

# Tipi di payload
PAYLOAD_TYPE_JSON = 0x01
PAYLOAD_TYPE_DATA = 0x02

# Schema JSON per validazione
MESSAGE_SCHEMA = {
    "type": "object",
    "properties": {
        "type": {"type": "string", "enum": [
            "key_rotation", "ping", "pong", "auth",
            "file_header", "file_resume_ack", "file_complete", "file_ack",
            # ðŸŸ¢ FASE 1: Definizione del Protocollo
            "list_files_request", "list_files_response", "download_file_request"
        ]},
        "version": {"type": "string"},
        "timestamp": {"type": "string"},
        "payload": {"type": "object"},
        "signature": {"type": "string"}
    },
    "required": ["type", "version", "timestamp", "payload"]
}

# ðŸŸ¢ MODIFICA: Nuovo Header (Aggiunti PayloadType (B) e Offset (Q))
# Magic(4s), Versione(I), PayloadType(B), Offset(Q), PayloadLen(I), KeyID(16s), Nonce(12s), Tag(16s)
HEADER_FORMAT = '!4sI B Q I 16s 12s 16s'
HEADER_PACKET_SIZE = struct.calcsize(HEADER_FORMAT) # = 65 byte

# Configurazione logging sicuro
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('secure_transfer.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

def _clear_memory(data: Any) -> None:
    """
    Pulizia sicura della memoria (Best-Effort in Python) per i dati sensibili.
    Funziona SOLO su tipi mutabili (es. bytearray).
    """
    if data is None:
        return
    try:
        if isinstance(data, bytearray):
            for i in range(len(data)):
                data[i] = 0
    except Exception:
        pass # Best effort

class RateLimiter:
    """Limita il rate delle richieste per prevenire DoS, con cleanup TTL automatico"""
    
    def __init__(self, max_requests: int, window_seconds: int):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        # Mapping client_id -> deque[timestamps]
        self.requests: Dict[str, deque] = {}
        self.last_seen: Dict[str, float] = {}
        self._lock = threading.Lock()
        self._running = True
        
        # ✅ FIX: Thread di cleanup automatico per prevenire memory leak
        self._cleanup_thread = threading.Thread(target=self._periodic_cleanup, daemon=True)
        self._cleanup_thread.start()
        
    def is_allowed(self, client_id: str) -> bool:
        """Verifica se una richiesta Ã¨ permessa"""
        with self._lock:
            now = time.time()
            if client_id not in self.requests:
                self.requests[client_id] = deque()
            if client_id not in self.last_seen:
                self.last_seen[client_id] = now
                
            # Rimuovi richieste vecchie (piÃ¹ vecchie della finestra)
            q = self.requests[client_id]
            while q and q[0] < now - self.window_seconds:
                q.popleft()
            
            # Verifica limite
            if len(q) >= self.max_requests:
                self.last_seen[client_id] = now
                return False
            
            # Aggiungi richiesta
            q.append(now)
            self.last_seen[client_id] = now
            return True

    def cleanup(self, older_than: int = 3600):
        """Rimuove client inattivi da richieste e last_seen per limitare memoria"""
        with self._lock:
            now = time.time()
            stale = [cid for cid, ts in self.last_seen.items() if ts < now - older_than]
            for cid in stale:
                self.requests.pop(cid, None)
                self.last_seen.pop(cid, None)
            if stale:
                logger.debug(f"RateLimiter cleanup: removed {len(stale)} stale entries")
    
    # ✅ FIX: Metodo di cleanup periodico per prevenire memory leak
    def _periodic_cleanup(self):
        """Cleanup periodico in background (ogni ora)"""
        while self._running:
            time.sleep(3600)  # Ogni ora
            try:
                self.cleanup(older_than=7200)  # Rimuovi client inattivi da 2+ ore
            except Exception as e:
                logger.error(f"RateLimiter periodic cleanup error: {e}")
    
    def shutdown(self):
        """Arresta il thread di cleanup"""
        self._running = False

class SecureKeyManager:
    """Gestione sicura delle chiavi con rotazione e pulizia memoria"""
    
    def __init__(self, identity: str):
        self.identity = identity
        self.current_key = None
        self.key_id = None
        self.key_timestamp = None
        # Lista di dizionari per le chiavi precedenti (chiave, id, timestamp)
        self.previous_keys: deque[Dict[str, Any]] = deque(maxlen=3) 
        self.rsa_private = None
        self.rsa_public = None
        self.peer_public_key = None
        self.shared_secret = None  # Per HMAC
        self._lock = threading.RLock()
        self._generate_rsa_keypair()
        self.failed_auth_attempts = 0
        
    def _generate_rsa_keypair(self):
        """Genera coppia di chiavi RSA 4096-bit"""
        self.rsa_private = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096,
            backend=default_backend()
        )
        self.rsa_public = self.rsa_private.public_key()
        
    def get_public_key_pem(self) -> bytes:
        """Restituisce la chiave pubblica in formato PEM"""
        return self.rsa_public.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def get_key_by_id(self, key_id: str) -> Optional[bytes]:
        """Recupera la chiave corrente o una precedente per ID"""
        with self._lock:
            if self.key_id == key_id:
                return self.current_key
            for entry in self.previous_keys:
                if entry['id'] == key_id:
                    return entry['key']
            return None
    def add_external_key_to_cache(self, key: bytes, key_id: str):
        """ðŸŸ¢ FIX (Analisi #7): Aggiunge una chiave esterna alla cache 'previous_keys'."""
        with self._lock:
            # Controlla se esiste giÃ  per evitare duplicati (improbabile)
            if self.get_key_by_id(key_id):
                return
                
            entry = {
                'key': key,
                'id': key_id,
                'timestamp': datetime.now()
            }
            if len(self.previous_keys) >= self.previous_keys.maxlen:
                old = self.previous_keys.popleft()
                # (Questa chiamata usa la versione corretta di _clear_memory 
                #  che gestisce 'bytes' non facendo nulla)
                _clear_memory(old.get('key'))
            
            self.previous_keys.append(entry)
        
    def generate_session_key(self) -> Tuple[bytes, str]:
        """Genera chiave di sessione e la ruota in modo sicuro"""
        with self._lock:
            # Rotazione chiave
            if self.current_key:
                old_key_entry = {
                    'key': self.current_key,
                    'id': self.key_id,
                    'timestamp': self.key_timestamp
                }
                if len(self.previous_keys) >= self.previous_keys.maxlen:
                    old = self.previous_keys.popleft()
                    _clear_memory(old['key'])
                
                self.previous_keys.append(old_key_entry)
            
            self.current_key = secrets.token_bytes(32)
            # Key id derivato deterministico dalla chiave per interoperabilitÃ 
            self.key_id = hashlib.sha256(self.current_key).hexdigest()[:16]
            self.key_timestamp = datetime.now()
            
            return self.current_key, self.key_id
    
    def establish_shared_secret(self, peer_public_key: bytes) -> bytes:
        """Stabilisce un segreto condiviso (Sender side)"""
        with self._lock:
            self.peer_public_key = serialization.load_pem_public_key(
                peer_public_key,
                backend=default_backend()
            )
            
            # ðŸŸ¢ CORREZIONE: Usa RSA-OAEP robusto per lo scambio di chiavi
            random_secret = secrets.token_bytes(32)
            
            encrypted = self.peer_public_key.encrypt(
                random_secret,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            # Deriva chiave HMAC dal segreto per il mittente
            self._derive_shared_secret(random_secret)
            
            _clear_memory(random_secret)
            
            return encrypted

    def decrypt_shared_secret(self, encrypted_secret: bytes) -> bytes:
        """Decifra il segreto condiviso dal peer (Receiver side)"""
        if not self.rsa_private:
            raise ValueError("Private key not loaded")

        with self._lock:
            decrypted_secret = self.rsa_private.decrypt(
                encrypted_secret,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            # Deriva chiave HMAC dal segreto
            self._derive_shared_secret(decrypted_secret)

            _clear_memory(decrypted_secret)

            return self.shared_secret
            
    def _derive_shared_secret(self, secret: bytes):
        """Deriva la chiave HMAC E la chiave AES (Key-Split) dal segreto scambiato"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=64,
            salt=b'secure_transfer_v2_split', 
            iterations=100000,
            backend=default_backend()
        )
        # Deriva il materiale crittografico
        derived_material = kdf.derive(secret)
        
        self.shared_secret = derived_material[:32] # Primi 32 per HMAC
        self.current_key = derived_material[32:]   # Ultimi 32 per AES
        
        self.key_id = hashlib.sha256(self.current_key).hexdigest()[:16]
        self.key_timestamp = datetime.now()

        # Pulisci il materiale intermedio
        _clear_memory(derived_material)
    
    def verify_signature(self, data: bytes, signature: bytes) -> bool:
        """Verifica firma HMAC con compare_digest per prevenire timing attacks"""
        if not self.shared_secret:
            return False
        
        expected = hmac.new(self.shared_secret, data, hashlib.sha256).digest()
        return hmac.compare_digest(expected, signature)
    
    def sign_data(self, data: bytes) -> bytes:
        """Firma dati con HMAC"""
        if not self.shared_secret:
            raise ValueError("Shared secret not established")
        return hmac.new(self.shared_secret, data, hashlib.sha256).digest()

class SecureProtocol:
    """Protocollo sicuro con validazione e autenticazione"""
    
    def __init__(self, key_manager: SecureKeyManager, received_messages_queue: deque):
        self.key_manager = key_manager
        self.rate_limiter = RateLimiter(MAX_REQUESTS_PER_WINDOW, RATE_LIMIT_WINDOW)
        self.received_messages = received_messages_queue
        
    def sanitize_filename(self, filename: str) -> str:
        """Sanitizza filename per prevenire path traversal"""
        filename = os.path.basename(filename)
        filename = re.sub(r'[^\w\s\-\.]', '', filename)
        
        # ðŸŸ¢ FIX (Analisi #5): Corregge la logica di troncamento
        if len(filename) > 255:
            name, ext = os.path.splitext(filename)
            
            # Limita l'estensione (es. max 20 caratteri + punto)
            if len(ext) > 21:
                ext = ext[:21]
                
            # Calcola la lunghezza massima del nome
            max_name_len = 255 - len(ext)
            name = name[:max_name_len]
            
            filename = name + ext
            
        reserved = ['CON', 'PRN', 'AUX', 'NUL', 'COM1', 'LPT1']
        name_upper = filename.upper().split('.')[0]
        if name_upper in reserved:
            filename = f"safe_{filename}"
        return filename or "unnamed_file"
    
    def encrypt_data(self, data: bytes, key: bytes = None) -> Tuple[bytes, str, bytes, bytes]:
        """Cifra con AES-256-GCM. Se viene fornita una chiave esterna, il key_id Ã¨ derivato dalla chiave stessa."""
        with self.key_manager._lock:
            if key is None:
                key = self.key_manager.current_key
                key_id = self.key_manager.key_id
            else:
                # Se la chiave esterna Ã¨ fornita, deriviamo un ID deterministico a partire dalla chiave
                key_id = hashlib.sha256(key).hexdigest()[:16]
                
                # ðŸŸ¢ FIX (Analisi #7): Caching chiave esterna
                # Aggiungila alla cache se non presente,
                # cosÃ¬ 'decrypt_data' puÃ² trovarla.
                if self.key_manager.get_key_by_id(key_id) is None:
                    self.key_manager.add_external_key_to_cache(key, key_id)
        
        if not key:
            raise ValueError("No encryption key available")
            
        nonce = secrets.token_bytes(12)
        
        # Cifratura AES-GCM usando cryptography
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
        encryptor = cipher.encryptor()
        
        ciphertext = encryptor.update(data) + encryptor.finalize()
        tag = encryptor.tag
        
        return ciphertext, key_id, nonce, tag
    
    def decrypt_data(self, ciphertext: bytes, key_id: str, nonce: bytes, tag: bytes) -> bytes:
        """Decifra con validazione"""
        with self.key_manager._lock:
            key = self.key_manager.get_key_by_id(key_id)
        
        if not key:
            logger.warning(f"Key ID not found: {key_id}")
            raise ValueError("Invalid or expired key")
        
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        
        try:
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            return plaintext
        except Exception as e:
            logger.error(f"Decryption failed: {e}")
            raise
    
    def _create_json_packet(self, msg_type: str, payload: Dict[str, Any], sign: bool = True) -> bytes:
        """Crea pacchetto JSON (Controllo) con firma e cifratura"""
        message = {
            'type': msg_type,
            'version': PROTOCOL_VERSION,
            'timestamp': datetime.now().isoformat(),
            'payload': payload
        }
        
        # Firma il messaggio se richiesto
        if sign and self.key_manager.shared_secret:
            message_bytes = json.dumps(message, sort_keys=True).encode('utf-8')
            signature = self.key_manager.sign_data(message_bytes)
            message['signature'] = signature.hex()
        
        # Valida schema (DoS)
        try:
            validate(instance=message, schema=MESSAGE_SCHEMA)
        except ValidationError as e:
            logger.error(f"Invalid message schema: {e}")
            raise ValueError("Invalid message structure")
        
        json_data = json.dumps(message).encode('utf-8')
        
        # Limita dimensione (DoS)
        if len(json_data) > MAX_PACKET_SIZE:
            raise ValueError(f"Packet too large: {len(json_data)} bytes")
        
        # Cifra
        ciphertext, key_id, nonce, tag = self.encrypt_data(json_data)
        
        # Header sicuro (Tipo 0x01, Offset 0)
        header = struct.pack(
            HEADER_FORMAT,
            b'SFTP',
            2,  # Versione protocollo
            PAYLOAD_TYPE_JSON,
            0,  # Offset (non applicabile per JSON)
            len(ciphertext),
            key_id.encode('utf-8')[:16].ljust(16, b'\x00'),
            nonce,
            tag
        )
        
        return header + ciphertext
    
    def _create_data_packet(self, data: bytes, offset: int) -> bytes:
        """Crea pacchetto Dati (Chunk) con cifratura"""
        if len(data) > MAX_PACKET_SIZE:
             raise ValueError(f"Data chunk too large: {len(data)} bytes")
             
        # Cifra
        ciphertext, key_id, nonce, tag = self.encrypt_data(data)

        # Header sicuro (Tipo 0x02, Offset specificato)
        header = struct.pack(
            HEADER_FORMAT,
            b'SFTP',
            2,  # Versione protocollo
            PAYLOAD_TYPE_DATA,
            offset,
            len(ciphertext),
            key_id.encode('utf-8')[:16].ljust(16, b'\x00'),
            nonce,
            tag
        )
        
        return header + ciphertext

    def parse_packet(self, data: bytes, client_id: str) -> Tuple[str, Any, int]:
        """
        Analizza pacchetto con rate limiting e controllo replay.
        Restituisce (tipo_pacchetto, payload, offset)
        'json' -> (payload Ã¨ un dict)
        'data' -> (payload sono bytes)
        """
        
        if len(data) < HEADER_PACKET_SIZE:
            raise ValueError("Packet too short")
        
        # Parse header
        magic, version, payload_type, offset, payload_len, key_id_raw, nonce, tag = struct.unpack(
            HEADER_FORMAT, data[:HEADER_PACKET_SIZE] 
        )
        
        if magic != b'SFTP':
            raise ValueError("Invalid magic number")
        
        if version != 2:
            raise ValueError(f"Unsupported protocol version: {version}")
        
        if payload_len > MAX_PACKET_SIZE:
            raise ValueError(f"Payload too large: {payload_len}")
        
        key_id = key_id_raw.rstrip(b'\x00').decode('utf-8')
        
        # Decifra
        ciphertext = data[HEADER_PACKET_SIZE : HEADER_PACKET_SIZE + payload_len]
        plaintext = self.decrypt_data(ciphertext, key_id, nonce, tag)
        
        # Gestione Tipi Payload
        if payload_type == PAYLOAD_TYPE_JSON:
            
            # Applica il Rate Limit SOLO ai pacchetti JSON (Comandi)
            if not self.rate_limiter.is_allowed(client_id):
                logger.warning(f"Rate limit exceeded for JSON command from {client_id}")
                raise ConnectionAbortedError(f"Rate limit exceeded for {client_id}")
            
            # Verifica replay: Hash del plaintext per ID messaggio
            message_id = hashlib.sha256(plaintext).hexdigest()
            if not self._check_and_add_message(message_id):
                raise ValueError("Replay attack detected")
            
            # Parse JSON con validazione
            try:
                message = json.loads(plaintext.decode('utf-8'))
                validate(instance=message, schema=MESSAGE_SCHEMA)
            except (json.JSONDecodeError, ValidationError) as e:
                logger.error(f"Invalid message format: {e}")
                raise ValueError("Invalid message format")
            
            # Verifica firma se presente
            if 'signature' in message:
                signature = bytes.fromhex(message['signature'])
                message_copy = message.copy()
                del message_copy['signature']
                message_bytes = json.dumps(message_copy, sort_keys=True).encode('utf-8')
                if not self.key_manager.verify_signature(message_bytes, signature):
                    logger.error("Invalid message signature")
                    raise ValueError("Invalid signature")
                
            # Verifica timestamp (anti-replay)
            try:
                msg_time = datetime.fromisoformat(message['timestamp'])
                # 5 minuti di tolleranza
                if abs((datetime.now() - msg_time).total_seconds()) > 300:
                    logger.warning("Message timestamp too old or in future")
                    raise ValueError("Invalid timestamp")
            except Exception:
                raise ValueError("Invalid timestamp format")
            
            return ('json', message, offset)
        
        elif payload_type == PAYLOAD_TYPE_DATA:
            # Ãˆ un chunk di dati binari, NON applicare rate limit o parsing JSON
            return ('data', plaintext, offset)
            
        else:
            raise ValueError(f"Unknown payload type: {payload_type}")
    
    def _check_and_add_message(self, message_id: str) -> bool:
        """Verifica replay e aggiunge ID messaggio al buffer FIFO (deque)"""
        if message_id in self.received_messages:
            logger.warning(f"Replay attack detected for message ID: {message_id}")
            return False
        
        self.received_messages.append(message_id)
        return True

class SecureFileTransferNode:
    """Nodo sicuro per trasferimento file con gestione DoS"""
    def __init__(self, mode: str, host: str = '0.0.0.0', port: int = DEFAULT_PORT):
        self.mode = mode
        self.host = host
        self.port = port
        self.identity = f"{mode}_{secrets.token_hex(4)}"
        # ðŸŸ¢ MODIFICA: Questo stato Ã¨ ora usato SOLO dal CLIENT
        # Il Server (handle_connection) crea le proprie istanze
        self.key_manager = SecureKeyManager(self.identity)
        self.received_messages: deque[str] = deque(maxlen=MAX_RECEIVED_MESSAGES) 
        self.protocol = SecureProtocol(self.key_manager, self.received_messages)
        
        # Limite basso per mitigare scan DoS (es. nmap -sV)
        self.connection_limiter = RateLimiter(max_requests=10, window_seconds=60)
        
        self.socket = None
        self.peer_socket: Optional[socket.socket] = None
        self.peer_address: Optional[str] = None
        self.running = False
        self.transfer_stats = { 
            'sent': 0, 'received': 0, 'errors': 0, 'auth_failures': 0 
        }
        self.active_threads = []
        self._connection_counter = 0
        self._counter_lock = threading.Lock()

        if self.mode == 'server':
            OUTPUT_DIR.mkdir(exist_ok=True)
            logger.info(f"Directory di output {OUTPUT_DIR.resolve()} assicurata.")

    # ðŸŸ¢ INIZIO REFACTORING THREAD-SAFE (Funzione #1)
    def _recv_all(self, sock: socket.socket, length: int) -> Optional[bytes]:
        """Riceve esattamente N bytes o None in caso di errore/timeout"""
        data = b''
        while len(data) < length:
            try:
                packet = sock.recv(length - len(data)) # USA sock
                if not packet:
                    # Ritorna None se lo socket Ã¨ chiuso (EOF)
                    return None
                data += packet
            except socket.timeout:
                logger.warning(f"Socket timeout during reception") # Rimosso peer_address
                return None
            except Exception as e:
                logger.error(f"Error receiving data: {e}")
                return None
        return data
    # ðŸŸ¢ FINE REFACTORING THREAD-SAFE (Funzione #1)

    # ðŸŸ¢ INIZIO REFACTORING THREAD-SAFE (Funzione #2)
    # ðŸŸ¢ MODIFICA: Accetta key_manager opzionale, usa self.key_manager come fallback
    def _perform_secure_handshake(self, sock: socket.socket, peer_addr: str, key_manager: Optional[SecureKeyManager] = None) -> bool:
        """Esegue l'handshake RSA-OAEP"""
        
        # Se key_manager non Ã¨ fornito (es. Client), usa l'istanza 'self'
        km = key_manager if key_manager else self.key_manager
        
        try:
            # 1. Invia chiave pubblica e ricevi chiave pubblica del peer
            public_key_pem = km.get_public_key_pem()
            sock.sendall(struct.pack('!I', len(public_key_pem)) + public_key_pem) # USA sock

            header_len = struct.calcsize('!I')
            header = self._recv_all(sock, header_len) # PASSA sock
            if not header: return False
            peer_key_len, = struct.unpack('!I', header)
            peer_key_pem = self._recv_all(sock, peer_key_len) # PASSA sock
            if not peer_key_pem: return False

            # 2. Scambia segreto (Iniziatore vs Risponditore)
            if self.mode == 'client':
                encrypted_secret = km.establish_shared_secret(peer_key_pem)
                sock.sendall(struct.pack('!I', len(encrypted_secret)) + encrypted_secret) # USA sock
                confirm_header = self._recv_all(sock, header_len) # PASSA sock
                if not confirm_header: return False
                confirm_len, = struct.unpack('!I', confirm_header)
                confirm_msg = self._recv_all(sock, confirm_len) # PASSA sock
                if confirm_msg != b"AUTH_OK": return False
            elif self.mode == 'server':
                secret_header = self._recv_all(sock, header_len) # PASSA sock
                if not secret_header: return False
                secret_len, = struct.unpack('!I', secret_header)
                encrypted_secret = self._recv_all(sock, secret_len) # PASSA sock
                if not encrypted_secret: return False
                km.decrypt_shared_secret(encrypted_secret)
                confirm_msg = b"AUTH_OK"
                sock.sendall(struct.pack('!I', len(confirm_msg)) + confirm_msg) # USA sock

            logger.info(f"Secure handshake successful with {peer_addr}") # USA peer_addr
            return True

        except Exception as e:
            logger.error(f"Handshake failed: {e}")
            self.transfer_stats['auth_failures'] += 1
            return False
    # ðŸŸ¢ FINE REFACTORING THREAD-SAFE (Funzione #2)

    # ðŸŸ¢ INIZIO REFACTORING THREAD-SAFE (Funzione #3)
    # ðŸŸ¢ MODIFICA: Accetta protocol opzionale, usa self.protocol come fallback
    def _read_and_parse_packet(self, sock: socket.socket, client_id: str, protocol: Optional[SecureProtocol] = None) -> Tuple[str, Any, int]:
        """Helper per leggere un pacchetto completo (Header + Payload) e parsarlo"""
        
        # Se protocol non Ã¨ fornito (es. Client), usa l'istanza 'self'
        proto = protocol if protocol else self.protocol
        
        # 1. Riceve header
        header = self._recv_all(sock, HEADER_PACKET_SIZE) # PASSA sock
        if not header:
            raise ConnectionAbortedError("Connection closed while reading header")

        # 2. Estrai la lunghezza del payload...
        magic, _, _, _, payload_len, *_ = struct.unpack(
            HEADER_FORMAT, header
        )
        if magic != b'SFTP':
            raise ValueError("Invalid magic number in _read_and_parse_packet")
        
        if payload_len > MAX_PACKET_SIZE:
            logger.error(f"Payload too large in header: {payload_len}")
            raise ValueError("Received too large payload size in header.")

        # 3. Riceve payload
        ciphertext = self._recv_all(sock, payload_len) # PASSA sock
        if not ciphertext:
            raise ConnectionAbortedError("Connection closed while reading payload")

        full_packet = header + ciphertext
        
        # 4. Parsa (usa la logica di protocol.parse_packet)
        # Questo solleverÃ  eccezioni in caso di fallimento decrypt/auth
        pkt_type, payload, offset = proto.parse_packet(full_packet, client_id)
        return pkt_type, payload, offset
    # ðŸŸ¢ FINE REFACTORING THREAD-SAFE (Funzione #3)

    # ðŸŸ¢ INIZIO REFACTORING THREAD-SAFE (Funzione #4)
    def _handle_connection(self, conn: socket.socket, addr: Tuple[str, int]):
        """Gestisce il traffico cifrato in un thread separato (LOGICA SERVER)"""
        
        thread_name = threading.current_thread().name
        host, port = addr
        # NON IMPOSTARE self.peer_address o self.peer_socket
        conn.settimeout(SOCKET_TIMEOUT) # USA conn
        
        logger.info(f"[{thread_name}] Incoming connection attempt from {host}:{port}")
        
        # Mitiga DoS da connection flood (es. nmap -sV) prima del costoso handshake
        if not self.connection_limiter.is_allowed(host):
            logger.warning(f"[{thread_name}] Connection rate limit (pre-handshake) exceeded for {host}. Closing.")
            self.transfer_stats['auth_failures'] += 1 # Contiamo come fallimento auth
            conn.close()
            # Usciamo *prima* di incrementare il _connection_counter
            return

        # Stato del trasferimento per questa connessione
        current_transfer: Dict[str, Any] = {}
        
        # ðŸŸ¢ MODIFICA: Dichiarazione variabili locali per lo stato
        key_manager: Optional[SecureKeyManager] = None
        protocol: Optional[SecureProtocol] = None
        
        try:
            # ðŸŸ¢ FIX (Analisi #8): Spostato l'incremento all'interno
            # del 'try' per garantire che 'finally' lo catturi sempre.
            with self._counter_lock:
                self._connection_counter += 1

            # ðŸŸ¢ INIZIO MODIFICA: Creazione stato locale per-thread
            # Ogni thread ha il suo KeyManager, la sua coda Anti-Replay, e il suo Protocollo.
            # Questo ISOLA le chiavi di sessione e risolve la race condition.
            thread_identity = f"{self.identity}_{host}:{port}_{secrets.token_hex(2)}"
            key_manager = SecureKeyManager(thread_identity)
            received_messages_queue: deque[str] = deque(maxlen=MAX_RECEIVED_MESSAGES) 
            protocol = SecureProtocol(key_manager, received_messages_queue)
            # ðŸŸ¢ FINE MODIFICA
            
            # 0. Controllo limite connessioni (DoS - Circuit breaker)
            # ðŸŸ¢ FIX (Analisi #9): Eseguito PRIMA dell'handshake costoso.
            if self._connection_counter > MAX_GLOBAL_CONNECTIONS:
                logger.error(f"Global connection limit reached ({MAX_GLOBAL_CONNECTIONS}). Closing connection from {host}.")
                conn.close() # USA conn
                return # 'finally' si occuperÃ  del decremento

            # 1. Handshake e autenticazione
            # ðŸŸ¢ MODIFICA: Passa il key_manager locale
            if not self._perform_secure_handshake(conn, host, key_manager):
                logger.error(f"[{thread_name}] Handshake failed. Closing connection.")
                return # 'finally' si occuperÃ  del decremento
            
            # ðŸŸ¢ INIZIO MODIFICA (Finding #1 - Idle Timeout)
            last_activity_time = time.time()
            # ðŸŸ¢ FINE MODIFICA

            # 2. Loop di comunicazione (State Machine)
            while self.running:
                
                # ðŸŸ¢ INIZIO MODIFICA (Finding #1 - Idle Timeout)
                # 2.0 Verifica idle timeout usando select
                now = time.time()
                remaining_idle_time = (last_activity_time + IDLE_TIMEOUT) - now
                
                if remaining_idle_time <= 0:
                    logger.warning(f"[{thread_name}] Closing connection from {host} due to idle timeout ({IDLE_TIMEOUT}s).")
                    break # Interrompi il loop, 'finally' pulirÃ 

                # Attendi il minimo tra il timeout di inattivitÃ  rimanente e il timeout del socket
                wait_time = min(remaining_idle_time, SOCKET_TIMEOUT)
                
                # Usa select per attendere dati in modo non bloccante (rispetto all'IDLE_TIMEOUT)
                ready_to_read, _, _ = select.select([conn], [], [], wait_time)
                
                if not ready_to_read:
                    # Select Ã¨ scaduto (o per 'wait_time' o per 'remaining_idle_time')
                    # Il loop rieseguirÃ  il check di remaining_idle_time all'inizio
                    continue
                # ðŸŸ¢ FINE MODIFICA

                # 2.1. Leggi e parsa il prossimo pacchetto (ora sappiamo ci sono dati)
                # ðŸŸ¢ MODIFICA: Passa il protocol locale
                pkt_type, payload, offset = self._read_and_parse_packet(conn, host, protocol)
                
                # ðŸŸ¢ INIZIO MODIFICA (Finding #1 - Idle Timeout)
                last_activity_time = time.time() # Resetta il timer DOPO attivitÃ 
                # ðŸŸ¢ FINE MODIFICA

                # 2.2. Gestione Pacchetti JSON (Comandi)
                if pkt_type == 'json':
                    msg_type = payload.get('type')
                    logger.info(f"[{thread_name}] Received JSON command: {msg_type}")
                    
                    if msg_type == 'ping':
                        logger.info(f"[{thread_name}] Responding with PONG.")
                        try:
                            # ðŸŸ¢ MODIFICA: Usa il protocol locale
                            pong_packet = protocol._create_json_packet('pong', {})
                            conn.sendall(pong_packet) # USA conn
                        except Exception as e:
                            logger.error(f"[{thread_name}] Failed to send PONG: {e}")
                            break # Interrompi se l'invio fallisce
                    
                    elif msg_type == 'file_header':
                        # ðŸŸ¢ MODIFICA: Usa il protocol locale
                        filename = protocol.sanitize_filename(payload['payload']['filename'])
                        total_size = int(payload['payload']['total_size'])
                        file_hash = payload['payload'].get('hash') # ðŸŸ¢ FIX (Analisi #10)
                        safe_path = OUTPUT_DIR / filename
                        
                       # ðŸŸ¢ FIX (Analisi #15): Applica MAX_FILE_SIZE
                        if total_size > MAX_FILE_SIZE:
                            logger.error(f"[{thread_name}] File '{filename}' exceeds MAX_FILE_SIZE ({total_size} > {MAX_FILE_SIZE}). Rejecting.")
                            # Invia un errore (best-effort) e chiudi
                            try:
                                err_packet = protocol._create_json_packet(
                                    'file_ack', 
                                    {'filename': filename, 'error': 'File too large'}
                                )
                                conn.sendall(err_packet)
                            except Exception:
                                pass
                            break # Interrompi il loop e chiudi la connessione

                        current_offset = 0
                        mode = 'wb'
                        
                        # Logica di Resume
                        if safe_path.exists():
                            current_offset = safe_path.stat().st_size
                            if current_offset < total_size:
                                logger.info(f"[{thread_name}] Resuming {filename} from offset {current_offset}")
                                mode = 'ab' # Append
                            elif current_offset == total_size:
                                logger.info(f"[{thread_name}] File {filename} already complete. Overwriting.")
                                current_offset = 0
                            else: # File locale corrotto/piÃ¹ grande
                                logger.warning(f"[{thread_name}] Local file {filename} is larger than expected ({current_offset} > {total_size}). Overwriting.")
                                current_offset = 0
                        
                        file_handle = safe_path.open(mode)
                        current_transfer = {'path': safe_path, 'handle': file_handle, 'total': total_size, 'hash': file_hash}                        
                        # Invia ACK con l'offset
                        # ðŸŸ¢ MODIFICA: Usa il protocol locale
                        ack_packet = protocol._create_json_packet(
                            'file_resume_ack', 
                            {'filename': filename, 'offset': current_offset}
                        )
                        conn.sendall(ack_packet) # USA conn

                    elif msg_type == 'file_complete':
                        if not current_transfer:
                            logger.warning(f"[{thread_name}] Received 'file_complete' without active transfer.")
                            continue
                        
                        filename = payload['payload']['filename']
                        logger.info(f"[{thread_name}] Transfer complete for {filename}")
                        current_transfer['handle'].close()

                        
                        # ðŸŸ¢ FIX (Analisi #10): Verifica hash
                        final_hash_ok = False
                        client_hash = current_transfer.get('hash')
                        file_path = current_transfer.get('path')

                        if client_hash and file_path and file_path.exists():
                            logger.info(f"[{thread_name}] Verifying hash for {file_path.name}...")
                            try:
                                server_hash_obj = hashlib.sha256()
                                with file_path.open('rb') as f_verify:
                                    while chunk := f_verify.read(BUFFER_SIZE * 10):
                                        server_hash_obj.update(chunk)
                                calculated_hash = server_hash_obj.hexdigest()

                                if hmac.compare_digest(calculated_hash, client_hash):
                                    logger.info(f"[{thread_name}] Hash verification SUCCESS")
                                    final_hash_ok = True
                                else:
                                    logger.error(f"[{thread_name}] HASH MISMATCH. Expected: {client_hash}, Got: {calculated_hash}")
                            except Exception as e:
                                logger.error(f"[{thread_name}] Failed to verify hash: {e}")
                        else:
                            logger.warning(f"[{thread_name}] Skipping hash check (no hash provided or file missing).")
                            final_hash_ok = True # Considera ok se saltato                        
                        # Invia ACK finale
                        # ðŸŸ¢ MODIFICA: Usa il protocol locale
                        ack_payload = {'filename': filename}
                        if not final_hash_ok:
                            ack_payload['error'] = 'Hash mismatch on server'
                        ack_packet = protocol._create_json_packet('file_ack', ack_payload)
                        conn.sendall(ack_packet) # USA conn
                        current_transfer = {}

                    # ðŸŸ¢ FASE 2: Implementazione Logica Server (List)
                    elif msg_type == 'list_files_request':
                        logger.info(f"[{thread_name}] Received list_files_request from {host}")
                        file_list = []
                        try:
                            for f in OUTPUT_DIR.glob('*'):
                                if f.is_file():
                                    file_list.append({'name': f.name, 'size': f.stat().st_size})
                            
                            response_packet = protocol._create_json_packet(
                                'list_files_response',
                                {'files': file_list}
                            )
                        except Exception as e:
                            logger.error(f"[{thread_name}] Failed to list directory: {e}")
                            response_packet = protocol._create_json_packet(
                                'list_files_response',
                                {'files': [], 'error': 'Failed to list directory'}
                            )
                        conn.sendall(response_packet)
                    
                    # ðŸŸ¢ FASE 2: Implementazione Logica Server (Download)
                    elif msg_type == 'download_file_request':
                        remote_filename = payload['payload'].get('filename')
                        logger.info(f"[{thread_name}] Received download_file_request for {remote_filename}")
                        
                        if not remote_filename:
                             err_packet = protocol._create_json_packet('file_ack', {'error': 'Missing filename'})
                             conn.sendall(err_packet)
                             continue
                        # ðŸŸ¢ FIX: Path Traversal (Information Leak)
                        # Rifiuta se il nome richiesto contiene componenti di percorso.
                        sanitized_name = protocol.sanitize_filename(remote_filename)
                        
                        if sanitized_name != remote_filename:
                            logger.warning(f"[{thread_name}] Path Traversal attempt detected (Name mismatch): {remote_filename} != {sanitized_name}")
                            err_packet = protocol._create_json_packet(
                                'file_ack', 
                                {'filename': remote_filename, 'error': 'File not found or access denied'}
                            )
                            conn.sendall(err_packet)
                            continue
                        # --- CRITICAL: Path Traversal Check ---
                        sanitized_name = protocol.sanitize_filename(remote_filename)
                        target_path = (OUTPUT_DIR / sanitized_name).resolve()
                        resolved_output_dir = OUTPUT_DIR.resolve()
                        
                        is_safe = False
                        try:
                            # Metodo preferito (Python 3.9+)
                            is_safe = target_path.is_relative_to(resolved_output_dir)
                        except AttributeError:
                            # Fallback per Python < 3.9
                            is_safe = str(target_path).startswith(str(resolved_output_dir))
                        
                        if not target_path.is_file() or not is_safe:
                            logger.warning(f"[{thread_name}] Path Traversal attempt or file not found for: {remote_filename}")
                            err_packet = protocol._create_json_packet(
                                'file_ack', 
                                {'filename': remote_filename, 'error': 'File not found or access denied'}
                            )
                            conn.sendall(err_packet)
                            continue
                        
                        # --- Fine Controllo Sicurezza ---
                        
                        logger.info(f"[{thread_name}] Starting send logic for {sanitized_name} to {host}")
                        # Avvia la logica di invio (bloccante per questo thread)
                        try:
                            # ðŸŸ¢ REFACTOR: Chiama la logica di invio unificata
                            # Passa il socket e il protocollo di *questo* thread
                            self._internal_send_file_logic(conn, protocol, target_path, None)
                        except Exception as e:
                            logger.error(f"[{thread_name}] Failed to send file {sanitized_name}: {e}")
                            # Errore giÃ  gestito/loggato da _internal_send_file_logic
                            break # Interrompi il loop, la connessione Ã¨ probabilmente morta


                # 2.3. Gestione Pacchetti DATA (Chunks)
                elif pkt_type == 'data':
                    if not current_transfer:
                        logger.warning(f"[{thread_name}] Received data chunk without active transfer. Discarding.")
                        continue
                        
                    handle = current_transfer['handle']
                    
                    # Scrivi nel file all'offset corretto
                    handle.seek(offset)
                    handle.write(payload)
                    
                    logger.debug(f"[{thread_name}] Wrote chunk to {current_transfer['path'].name} at offset {offset}. Total {offset + len(payload)} / {current_transfer['total']}")

            logger.info(f"[{thread_name}] Connection closed gracefully.")

        # ðŸŸ¢ CORREZIONE: Gestione pulita della disconnessione
        except ConnectionAbortedError as e:
            # Il client si Ã¨ disconnesso (normale, dopo il file_ack o timeout)
            logger.info(f"[{thread_name}] Client connection closed: {e}")
        except ValueError as e:
            # Errore nel protocollo (numero magico, replay, JSON malformato, firma)
            logger.error(f"[{thread_name}] Protocol error: {e}", exc_info=False)
            self.transfer_stats['errors'] += 1
        except Exception as e:
            # Errore socket imprevisto o altro
            logger.error(f"[{thread_name}] Unhandled connection error: {e}", exc_info=True)
            self.transfer_stats['errors'] += 1
        finally:
            # Assicurati che l'handle del file sia chiuso
            if current_transfer.get('handle'):
                try:
                    current_transfer['handle'].close()
                except Exception as e:
                    logger.error(f"[{thread_name}] Failed to close file handle: {e}")
            
            # ðŸŸ¢ MODIFICA: Pulizia sicura delle chiavi locali del thread
            if key_manager:
                if key_manager.current_key:
                    _clear_memory(key_manager.current_key)
                if key_manager.shared_secret:
                    _clear_memory(key_manager.shared_secret)

            try:
                conn.close() # USA conn
            except Exception:
                pass
            with self._counter_lock:
                self._connection_counter -= 1

    def start_server(self):
        """Avvia server sicuro"""
        self.running = True
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Permette il riuso dell'indirizzo
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        # ðŸŸ¢ MODIFICA: Bindando a self.port (che puÃ² essere 0)
        self.socket.bind((self.host, self.port))
        
        # ðŸŸ¢ MODIFICA: Recupera la porta reale assegnata dal SO
        # Se self.port era 0, ora conterrÃ  la porta effimera
        actual_port = self.socket.getsockname()[1]
        self.port = actual_port
        
        self.socket.listen(5) # Backlog limitato
        
        # Il log ora mostrerÃ  la porta corretta
        logger.info(f"Server listening on {self.host}:{self.port}...")
        logger.info(f"File verranno salvati in: {OUTPUT_DIR.resolve()}")

        try:
            while self.running:
                try:
                    conn, addr = self.socket.accept()
                    # Rimuovi i thread completati per mantenere pulito il pool
                    self.active_threads = [t for t in self.active_threads if t.is_alive()]
                    
                    if len(self.active_threads) < MAX_GLOBAL_CONNECTIONS:
                        client_thread = threading.Thread(
                            target=self._handle_connection, 
                            args=(conn, addr),
                            name=f"ClientThread-{addr[0]}"
                        )
                        client_thread.start()
                        self.active_threads.append(client_thread)
                    else:
                        logger.warning("Global thread limit reached, refusing connection.")
                        conn.close() # Rifiuta connessione (Circuit Breaker)
                        
                except socket.timeout:
                    continue # Timeout per controllare self.running
                except OSError as e:
                    if self.running:
                        logger.error(f"Socket error in server loop: {e}")
                    break
        finally:
            self.shutdown()

    def connect_to_server(self, host: str, port: int):
        """Connette al server in modo sicuro ed esegue l'handshake"""
        self.running = True
        self.peer_address = host
        self.peer_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.peer_socket.settimeout(SOCKET_TIMEOUT)
        
        try:
            logger.info(f"Connecting to {host}:{port}...")
            self.peer_socket.connect((host, port))
            
            # ðŸŸ¢ INIZIO REFACTORING THREAD-SAFE (Client)
            # Handshake (NON passa istanze, usa il fallback a self.*)
            if not self._perform_secure_handshake(self.peer_socket, self.peer_address):
                raise ConnectionRefusedError("Secure handshake failed.")
            # ðŸŸ¢ FINE REFACTORING THREAD-SAFE (Client)
                
            logger.info("Connection successful. Ready to send files.")
            # Non avvia un loop, resta in attesa di comandi (es. send_file)

        except (socket.error, ConnectionRefusedError) as e:
            logger.error(f"Connection failed: {e}")
            self.shutdown() # Chiude se l'handshake fallisce
            raise # Rilancia l'eccezione

    # ðŸŸ¢ FASE 2: REFACTOR (Sposta logica da send_file a helper)
    def _internal_send_file_logic(
        self, 
        sock: socket.socket, 
        protocol: SecureProtocol, 
        local_path: Path, 
        progress_callback: Optional[callable] = None
    ):
        """
        Logica di invio file interna, usata sia dal client (upload) 
        che dal server (download).
        """
        
        # Determina client_id per il parsing dei pacchetti di risposta
        try:
            client_id = str(sock.getpeername())
        except Exception:
            client_id = "unknown_peer"

        try:
            total_size = local_path.stat().st_size
            filename = protocol.sanitize_filename(local_path.name)
            
            # Calcola hash
            logger.info(f"[{client_id}] Calculating SHA-256 hash for {filename}...")
            file_hash_obj = hashlib.sha256()
            with local_path.open('rb') as f_hash:
                while chunk := f_hash.read(BUFFER_SIZE * 10):
                    file_hash_obj.update(chunk)
            file_hash = file_hash_obj.hexdigest()

            # 1. Invia 'file_header'
            logger.info(f"[{client_id}] Sending file header for {filename} ({total_size} bytes)")
            header_payload = {
                'filename': filename, 
                'total_size': total_size, 
                'hash': file_hash,
                'timestamp': datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
            }
            header_packet = protocol._create_json_packet('file_header', header_payload)
            sock.sendall(header_packet)
            self.transfer_stats['sent'] += 1

            # 2. Attendi ACK/Resume
            pkt_type, response, _ = self._read_and_parse_packet(sock, client_id, protocol)
            self.transfer_stats['received'] += 1
            
            if pkt_type != 'json' or response.get('type') != 'file_resume_ack':
                error = response.get('payload', {}).get('error', 'Unknown error')
                raise Exception(f"Peer did not acknowledge file header. Got: {response.get('type')}. Error: {error}")
                
            start_offset = response['payload'].get('offset', 0)
            if start_offset > total_size:
                logger.error(f"[{client_id}] Peer offset {start_offset} is larger than file size {total_size}. Aborting.")
                raise Exception("Invalid resume offset from peer.")
            
            logger.info(f"[{client_id}] Peer ACK. Starting upload from offset: {start_offset}")

            # 3. Invia Chunks
            chunk_ba = bytearray(BUFFER_SIZE)
            chunk_view = memoryview(chunk_ba)

            try:
                with local_path.open('rb') as f:
                    f.seek(start_offset)
                    current_offset = start_offset
                    
                    while self.running and current_offset < total_size:
                        read_len = f.readinto(chunk_ba)
                        
                        if read_len == 0:
                            if current_offset < total_size:
                                logger.error(f"[{client_id}] EOF reached prematurely at {current_offset} (expected {total_size}). File modified?")
                                err_packet = protocol._create_json_packet(
                                    'file_complete', 
                                    {'filename': filename, 'error': 'File read error (EOF)'}
                                )
                                sock.sendall(err_packet)
                            break 
                        
                        if read_len < BUFFER_SIZE:
                            chunk_to_send = chunk_view[:read_len]
                        else:
                            chunk_to_send = chunk_ba
                        
                        data_packet = protocol._create_data_packet(chunk_to_send, current_offset)
                        sock.sendall(data_packet)
                        self.transfer_stats['sent'] += 1
                        
                        current_offset += read_len
                        
                        if progress_callback:
                            try:
                                progress_callback(filename, current_offset, total_size)
                            except Exception as cb_e:
                                logger.warning(f"Progress callback failed: {cb_e}")
            finally:
                _clear_memory(chunk_ba)
                
            if not self.running:
                logger.warning(f"[{client_id}] Transfer interrupted during chunk sending.")
                return

            # 4. Invia 'file_complete'
            logger.info(f"[{client_id}] File send complete for {filename}. Sending 'file_complete' message.")
            complete_packet = protocol._create_json_packet(
                'file_complete', 
                {'filename': filename, 'total_size': total_size}
            )
            sock.sendall(complete_packet)
            self.transfer_stats['sent'] += 1
            
            # 5. Attendi ACK finale
            pkt_type, response, _ = self._read_and_parse_packet(sock, client_id, protocol)
            self.transfer_stats['received'] += 1
            if pkt_type == 'json' and response.get('type') == 'file_ack':
                error = response.get('payload', {}).get('error')
                if error:
                    logger.error(f"[{client_id}] Peer reported error in final ACK: {error}")
                else:
                    logger.info(f"[{client_id}] Peer acknowledged file_complete for {filename}.")
            else:
                logger.warning(f"[{client_id}] Did not receive final file_ack. Got: {response.get('type')}")

        except Exception as e:
            logger.error(f"[{client_id}] Error during internal_send_file_logic: {e}", exc_info=True)
            self.transfer_stats['errors'] += 1
            raise # Rilancia l'eccezione

    def send_file(self, local_filepath: str, progress_callback: Optional[callable] = None):
        """Invia un file al server connesso (LOGICA CLIENT - Upload)"""
        if not self.running or not self.peer_socket:
            raise ConnectionError("Not connected to server.")
        
        local_path = Path(local_filepath)
        if not local_path.exists() or not local_path.is_file():
            raise FileNotFoundError(f"File not found: {local_filepath}")
        
        # ✅ FIX: Validazione MAX_FILE_SIZE lato client
        file_size = local_path.stat().st_size
        if file_size > MAX_FILE_SIZE:
            raise ValueError(f"File too large: {file_size} bytes (max: {MAX_FILE_SIZE} bytes = {MAX_FILE_SIZE // (1024**3)}GB)")
        
        # Chiama la logica unificata
        self._internal_send_file_logic(
            self.peer_socket, 
            self.protocol, 
            local_path, 
            progress_callback
        )
            
    # ðŸŸ¢ FASE 1: Implementa Nuovi Metodi Client (List)
    def list_files(self) -> list:
        """Richiede l'elenco dei file remoti (LOGICA CLIENT)"""
        if not self.running or not self.peer_socket:
            raise ConnectionError("Not connected to server.")
        
        logger.info("Requesting remote file list...")
        try:
            # 1. Invia 'list_files_request'
            request_packet = self.protocol._create_json_packet('list_files_request', {})
            self.peer_socket.sendall(request_packet)
            self.transfer_stats['sent'] += 1

            # 2. Attendi 'list_files_response'
            pkt_type, response, _ = self._read_and_parse_packet(self.peer_socket, self.peer_address)
            self.transfer_stats['received'] += 1

            if pkt_type == 'json' and response.get('type') == 'list_files_response':
                payload = response['payload']
                if 'error' in payload:
                    logger.error(f"Server error listing files: {payload['error']}")
                    return []
                logger.info(f"Received file list ({len(payload.get('files', []))} files).")
                return payload.get('files', [])
            else:
                logger.error(f"Invalid response from server for list_files. Got: {response.get('type')}")
                return []
        except Exception as e:
            logger.error(f"Error during list_files: {e}", exc_info=True)
            self.transfer_stats['errors'] += 1
            raise
            
    # ðŸŸ¢ FASE 1: Implementa Nuovi Metodi Client (Download)
    def download_file(self, remote_filename: str, local_save_path: Path, progress_callback: Optional[callable] = None):
        """Richiede un file dal server (LOGICA CLIENT - Download)"""
        if not self.running or not self.peer_socket:
            raise ConnectionError("Not connected to server.")
        
        logger.info(f"Requesting download for '{remote_filename}' to '{local_save_path}'")
        
        # Stato del trasferimento (lato ricezione)
        current_transfer: Dict[str, Any] = {}
        
        try:
            # 1. Invia 'download_file_request'
            request_packet = self.protocol._create_json_packet(
                'download_file_request', 
                {'filename': remote_filename}
            )
            self.peer_socket.sendall(request_packet)
            self.transfer_stats['sent'] += 1
            
            # 2. Inizia la state machine di ricezione (replica _handle_connection)
            while self.running:
                # 2.1. Leggi il prossimo pacchetto
                pkt_type, payload, offset = self._read_and_parse_packet(self.peer_socket, self.peer_address)
                self.transfer_stats['received'] += 1
                
                # 2.2. Gestione Pacchetti JSON
                if pkt_type == 'json':
                    msg_type = payload.get('type')
                    
                    # Server invia 'file_header'
                    if msg_type == 'file_header':
                        filename = self.protocol.sanitize_filename(payload['payload']['filename'])
                        total_size = int(payload['payload']['total_size'])
                        file_hash = payload['payload'].get('hash')
                        
                        # Assicura che la directory esista
                        local_save_path.parent.mkdir(parents=True, exist_ok=True)
                        
                        current_offset = 0
                        mode = 'wb'
                        
                        # Logica Resume
                        if local_save_path.exists():
                            current_offset = local_save_path.stat().st_size
                            if current_offset < total_size:
                                logger.info(f"Resuming download {filename} from offset {current_offset}")
                                mode = 'ab'
                            else:
                                logger.info(f"File {filename} already complete. Overwriting.")
                                current_offset = 0
                        
                        file_handle = local_save_path.open(mode)
                        current_transfer = {'path': local_save_path, 'handle': file_handle, 'total': total_size, 'hash': file_hash}
                        
                        # Invia ACK
                        ack_packet = self.protocol._create_json_packet(
                            'file_resume_ack',
                            {'filename': filename, 'offset': current_offset}
                        )
                        self.peer_socket.sendall(ack_packet)
                        self.transfer_stats['sent'] += 1
                    
                    # Server invia 'file_complete'
                    elif msg_type == 'file_complete':
                        if not current_transfer:
                            logger.warning("Received 'file_complete' without active transfer.")
                            continue
                        
                        filename = payload['payload']['filename']
                        logger.info(f"Download complete for {filename}. Verifying...")
                        current_transfer['handle'].close()

                        # Verifica Hash
                        final_hash_ok = False
                        client_hash = current_transfer.get('hash')
                        file_path = current_transfer.get('path')

                        if client_hash and file_path and file_path.exists():
                            try:
                                local_hash_obj = hashlib.sha256()
                                with file_path.open('rb') as f_verify:
                                    while chunk := f_verify.read(BUFFER_SIZE * 10):
                                        local_hash_obj.update(chunk)
                                calculated_hash = local_hash_obj.hexdigest()

                                if hmac.compare_digest(calculated_hash, client_hash):
                                    logger.info("Hash verification SUCCESS")
                                    final_hash_ok = True
                                else:
                                    logger.error(f"HASH MISMATCH. Expected: {client_hash}, Got: {calculated_hash}")
                            except Exception as e:
                                logger.error(f"Failed to verify hash: {e}")
                        else:
                            logger.warning("Skipping hash check (no hash provided or file missing).")
                            final_hash_ok = True # OK se saltato

                        # Invia ACK finale
                        ack_payload = {'filename': filename}
                        if not final_hash_ok:
                            ack_payload['error'] = 'Hash mismatch on client'
                        ack_packet = self.protocol._create_json_packet('file_ack', ack_payload)
                        self.peer_socket.sendall(ack_packet)
                        self.transfer_stats['sent'] += 1
                        
                        logger.info(f"File {filename} successfully downloaded to {file_path}.")
                        current_transfer = {}
                        break # Fine del download

                    # Server invia 'file_ack' (spesso per errori)
                    elif msg_type == 'file_ack':
                        error = payload.get('payload', {}).get('error')
                        if error:
                            logger.error(f"Server sent an error: {error}")
                            if current_transfer.get('handle'):
                                current_transfer['handle'].close()
                            current_transfer = {}
                            break # Interrompi in caso di errore
                        
                # 2.3. Gestione Pacchetti DATA
                elif pkt_type == 'data':
                    if not current_transfer:
                        logger.warning("Received data chunk without active transfer. Discarding.")
                        continue
                        
                    handle = current_transfer['handle']
                    handle.seek(offset)
                    handle.write(payload)
                    
                    current_bytes = offset + len(payload)
                    if progress_callback:
                        try:
                            progress_callback(remote_filename, current_bytes, current_transfer['total'])
                        except Exception as cb_e:
                            logger.warning(f"Progress callback failed: {cb_e}")
                    
            logger.info("Download logic complete.")

        except Exception as e:
            logger.error(f"Error during download_file: {e}", exc_info=True)
            self.transfer_stats['errors'] += 1
            if current_transfer.get('handle'):
                try:
                    current_transfer['handle'].close()
                except Exception:
                    pass
            raise

    def shutdown(self):
        """Spegnimento sicuro"""
        self.running = False
        if self.socket:
            try:
                self.socket.close()
            except:
                pass
        if self.peer_socket:
            try:
                self.peer_socket.close()
            except:
                pass
        
        # Pulizia chiavi correnti (Best-effort)
        # ðŸŸ¢ NOTA: Questo ora pulisce solo le chiavi del CLIENT
        # Le chiavi del SERVER sono pulite nel 'finally' di _handle_connection
        if self.key_manager.current_key:
            _clear_memory(self.key_manager.current_key)
            self.key_manager.current_key = None
        if self.key_manager.shared_secret:
            _clear_memory(self.key_manager.shared_secret)
            self.key_manager.shared_secret = None
            
        logger.info("Node shut down.")

# Callback di esempio per il progresso
def simple_progress_callback(filename: str, current_bytes: int, total_bytes: int):
    """Callback di progresso da passare a send_file"""
    percent = (current_bytes / total_bytes) * 100
    print(f"\rProgresso: {filename} - {current_bytes}/{total_bytes} bytes ({percent:.2f}%)", end="")
    if current_bytes == total_bytes:
        print("\nTrasferimento completato.")

def main():
    parser = argparse.ArgumentParser(description="Secure File Transfer Node (v2.6 - Bidirectional)")
    parser.add_argument('--mode', choices=['server', 'client'], required=True, help='Run as server or client')
    parser.add_argument('--host', type=str, default='0.0.0.0', help='Binding host IP for server')
    parser.add_argument('--port', type=int, default=DEFAULT_PORT, help='Port number')
    parser.add_argument('--connect', type=str, help='Server IP:Port to connect (client mode)')
    
    # Argomenti CLI
    parser.add_argument('--file', type=str, help='Path to the file to UPLOAD (client mode)')
    parser.add_argument('--list', action='store_true', help='List remote files on server (client mode)')
    parser.add_argument('--download', type=str, help='Filename of the remote file to DOWNLOAD (client mode)')
    parser.add_argument('--output', type=str, default='.', help='Local directory or path to save downloaded file (default: current dir)')
    
    args = parser.parse_args()
    
    node = SecureFileTransferNode(args.mode, args.host, args.port)
    
    try:
        if args.mode == 'server':
            node.start_server()
        else:
            # ModalitÃ  Client
            if not args.connect:
                print("[ERROR] Specify --connect SERVER_IP:PORT for client mode")
                return
            
            # Verifica che almeno un'azione sia specificata
            if not args.file and not args.list and not args.download:
                print("[ERROR] Client mode requires an action: --file (upload), --list, or --download")
                parser.print_help()
                return
            
            # Controlla azioni mutuamente esclusive
            action_count = sum([bool(args.file), bool(args.list), bool(args.download)])
            if action_count > 1:
                print("[ERROR] --file, --list, and --download are mutually exclusive actions.")
                return

            # Parsing connessione server
            server_host = args.connect
            server_port = DEFAULT_PORT
            if ':' in args.connect:
                try:
                    server_host, port_str = args.connect.rsplit(':', 1)
                    server_port = int(port_str)
                except ValueError:
                    print("[ERROR] Invalid server address format or port number")
                    return
            
            if server_port < 1024 or server_port > 65535:
                print("[ERROR] Invalid port number")
                return

            try:
                socket.gethostbyname(server_host)
                try:
                    ipaddress.ip_address(server_host)
                except ValueError:
                    pass
            except socket.gaierror:
                print(f"[ERROR] Cannot resolve host: {server_host}")
                return

            # ✅ FIX: Validazione percorso client migliorata con controllo sovrascrittura
            # Validazione percorso client
            local_save_path_for_download: Optional[Path] = None
            temp_download_path: Optional[Path] = None  # Per download temporaneo

            if args.download:
                remote_filename_to_request = args.download
                safe_local_filename = os.path.basename(remote_filename_to_request)
                if not safe_local_filename:
                     print(f"[ERROR] Invalid remote filename: {remote_filename_to_request}")
                     return

                local_save_dir = Path(args.output).resolve()
                
                if local_save_dir.is_dir():
                    local_save_path_for_download = local_save_dir / safe_local_filename
                else:
                    local_save_path_for_download = local_save_dir
                
                # Se file esiste e utente vuole overwrite, usa nome temporaneo
                if local_save_path_for_download.exists():
                    file_size = local_save_path_for_download.stat().st_size
                    print(f"[WARNING] File '{local_save_path_for_download}' already exists ({file_size} bytes).")
                    
                    try:
                        user_input = input("Resume download or overwrite? (r=resume, o=overwrite, c=cancel): ").lower()
                        if user_input == 'c':
                            print("Download cancelled by user.")
                            return
                        elif user_input == 'o':
                            # Scarica con nome temporaneo per sicurezza
                            temp_download_path = local_save_path_for_download.parent / f".tmp_{safe_local_filename}.{os.getpid()}"
                            print(f"Downloading to temporary file first for safety...")
                            logger.info(f"Using temporary path for overwrite: {temp_download_path}")
                        elif user_input == 'r':
                            pass  # Resume normale
                        else:
                            print("Invalid choice. Use 'r' (resume), 'o' (overwrite), or 'c' (cancel).")
                            return
                    except (EOFError, KeyboardInterrupt):
                        print("\nDownload cancelled.")
                        return
                
                print(f"Downloading '{remote_filename_to_request}' to '{local_save_path_for_download}'...")

                try:
                    local_save_path_for_download.parent.mkdir(parents=True, exist_ok=True)
                    test_file = local_save_path_for_download.parent / f".test_write_{os.getpid()}"
                    try:
                        test_file.touch()
                        test_file.unlink()
                    except (PermissionError, OSError) as e:
                        print(f"[ERROR] Cannot write to directory: {local_save_path_for_download.parent}")
                        print(f"Details: {e}")
                        return
                except Exception as e:
                    print(f"[ERROR] Path validation error: {e}")
                    return
            
            # Esegui la logica client
            try:
                node.connect_to_server(server_host, server_port)
                
                if args.file:
                    print(f"Uploading {args.file}...")
                    node.send_file(args.file, progress_callback=simple_progress_callback)
                
                elif args.list:
                    print("Requesting file list from server...")
                    files = node.list_files()
                    if files:
                        print("\n--- File sul Server ---")
                        for f in files:
                            print(f"  - {f['name']} ({f['size']} bytes)")
                        print("-----------------------")
                    else:
                        print("Nessun file trovato o errore del server.")
                
                elif args.download:
                    # Usa path temporaneo se overwrite, altrimenti path normale
                    actual_download_path = temp_download_path if temp_download_path else local_save_path_for_download
                    
                    node.download_file(
                        args.download,
                        actual_download_path,
                        progress_callback=simple_progress_callback
                    )
                    
                    # Se download riuscito con file temporaneo, sostituisci l'originale
                    if temp_download_path and actual_download_path.exists():
                        try:
                            # Elimina il vecchio file
                            if local_save_path_for_download.exists():
                                local_save_path_for_download.unlink()
                                logger.info(f"Deleted old file: {local_save_path_for_download}")
                            
                            # Rinomina temporaneo -> definitivo
                            temp_download_path.rename(local_save_path_for_download)
                            logger.info(f"Renamed {temp_download_path} -> {local_save_path_for_download}")
                            print(f"File successfully replaced: {local_save_path_for_download}")
                        except Exception as e:
                            print(f"[ERROR] Failed to replace file: {e}")
                            print(f"Downloaded file kept as: {temp_download_path}")
                    
            except (ConnectionRefusedError, FileNotFoundError, Exception) as e:
                logger.error(f"Client operation failed: {e}")
                # Se fallisce con file temporaneo, eliminalo
                if temp_download_path and temp_download_path.exists():
                    try:
                        temp_download_path.unlink()
                        logger.info(f"Cleaned up temporary file: {temp_download_path}")
                    except Exception:
                        pass
            finally:
                node.shutdown()
            
    except KeyboardInterrupt:
        logger.info("User interrupt, shutting down.")
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
    finally:
        node.shutdown()

if __name__ == '__main__':
    main()