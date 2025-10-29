#!/usr/bin/env python3
"""
Sistema di Trasferimento File Cifrato con Sicurezza Rafforzata
Versione corretta con tutte le vulnerabilità risolte
(Refactoring v2.5: Thread-safe state-per-thread)
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
from pathlib import Path
from typing import Tuple, Optional, Dict, Any, Set
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding as sym_padding
from datetime import datetime, timedelta
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
            "file_header", "file_resume_ack", "file_complete", "file_ack"
        ]},
        "version": {"type": "string"},
        "timestamp": {"type": "string"},
        "payload": {"type": "object"},
        "signature": {"type": "string"}
    },
    "required": ["type", "version", "timestamp", "payload"]
}

# 🟢 MODIFICA: Nuovo Header (Aggiunti PayloadType (B) e Offset (Q))
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

def _clear_memory(data: bytes) -> None:
    """
    Pulizia sicura della memoria (Best-Effort in Python) per i dati sensibili.
    """
    if data and hasattr(data, '__len__'):
        try:
            if isinstance(data, bytearray):
                for i in range(len(data)):
                    data[i] = 0
            elif isinstance(data, bytes):
                temp = bytearray(data)
                for i in range(len(temp)):
                    temp[i] = 0
                del temp
        except:
            pass # Best effort

class RateLimiter:
    """Limita il rate delle richieste per prevenire DoS, con cleanup TTL"""
    
    def __init__(self, max_requests: int, window_seconds: int):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        # Mapping client_id -> deque[timestamps]
        self.requests: Dict[str, deque] = {}
        self.last_seen: Dict[str, float] = {}
        self._lock = threading.Lock()
        
    def is_allowed(self, client_id: str) -> bool:
        """Verifica se una richiesta è permessa"""
        with self._lock:
            now = time.time()
            if client_id not in self.requests:
                self.requests[client_id] = deque()
            if client_id not in self.last_seen:
                self.last_seen[client_id] = now
                
            # Rimuovi richieste vecchie (più vecchie della finestra)
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
            # Key id derivato deterministico dalla chiave per interoperabilità
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
            
            # 🟢 CORREZIONE: Usa RSA-OAEP robusto per lo scambio di chiavi
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
        if len(filename) > 255:
            name, ext = os.path.splitext(filename)
            filename = name[:240] + ext
        reserved = ['CON', 'PRN', 'AUX', 'NUL', 'COM1', 'LPT1']
        name_upper = filename.upper().split('.')[0]
        if name_upper in reserved:
            filename = f"safe_{filename}"
        return filename or "unnamed_file"
    
    def encrypt_data(self, data: bytes, key: bytes = None) -> Tuple[bytes, str, bytes, bytes]:
        """Cifra con AES-256-GCM. Se viene fornita una chiave esterna, il key_id è derivato dalla chiave stessa."""
        with self.key_manager._lock:
            if key is None:
                key = self.key_manager.current_key
                key_id = self.key_manager.key_id
            else:
                # Se la chiave esterna è fornita, deriviamo un ID deterministico a partire dalla chiave
                key_id = hashlib.sha256(key).hexdigest()[:16]
        
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
        'json' -> (payload è un dict)
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
            # È un chunk di dati binari, NON applicare rate limit o parsing JSON
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
        # 🟢 MODIFICA: Questo stato è ora usato SOLO dal CLIENT
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

    # 🟢 INIZIO REFACTORING THREAD-SAFE (Funzione #1)
    def _recv_all(self, sock: socket.socket, length: int) -> Optional[bytes]:
        """Riceve esattamente N bytes o None in caso di errore/timeout"""
        data = b''
        while len(data) < length:
            try:
                packet = sock.recv(length - len(data)) # USA sock
                if not packet:
                    # Ritorna None se lo socket è chiuso (EOF)
                    return None
                data += packet
            except socket.timeout:
                logger.warning(f"Socket timeout during reception") # Rimosso peer_address
                return None
            except Exception as e:
                logger.error(f"Error receiving data: {e}")
                return None
        return data
    # 🟢 FINE REFACTORING THREAD-SAFE (Funzione #1)

    # 🟢 INIZIO REFACTORING THREAD-SAFE (Funzione #2)
    # 🟢 MODIFICA: Accetta key_manager opzionale, usa self.key_manager come fallback
    def _perform_secure_handshake(self, sock: socket.socket, peer_addr: str, key_manager: Optional[SecureKeyManager] = None) -> bool:
        """Esegue l'handshake RSA-OAEP"""
        
        # Se key_manager non è fornito (es. Client), usa l'istanza 'self'
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
    # 🟢 FINE REFACTORING THREAD-SAFE (Funzione #2)

    # 🟢 INIZIO REFACTORING THREAD-SAFE (Funzione #3)
    # 🟢 MODIFICA: Accetta protocol opzionale, usa self.protocol come fallback
    def _read_and_parse_packet(self, sock: socket.socket, client_id: str, protocol: Optional[SecureProtocol] = None) -> Tuple[str, Any, int]:
        """Helper per leggere un pacchetto completo (Header + Payload) e parsarlo"""
        
        # Se protocol non è fornito (es. Client), usa l'istanza 'self'
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
        # Questo solleverà eccezioni in caso di fallimento decrypt/auth
        pkt_type, payload, offset = proto.parse_packet(full_packet, client_id)
        return pkt_type, payload, offset
    # 🟢 FINE REFACTORING THREAD-SAFE (Funzione #3)

    # 🟢 INIZIO REFACTORING THREAD-SAFE (Funzione #4)
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

        # Spostato DOPO il check del rate-limit
        with self._counter_lock:
            self._connection_counter += 1
        
        # Stato del trasferimento per questa connessione
        current_transfer: Dict[str, Any] = {}
        
        # 🟢 MODIFICA: Dichiarazione variabili locali per lo stato
        key_manager: Optional[SecureKeyManager] = None
        protocol: Optional[SecureProtocol] = None
        
        try:
            # 🟢 INIZIO MODIFICA: Creazione stato locale per-thread
            # Ogni thread ha il suo KeyManager, la sua coda Anti-Replay, e il suo Protocollo.
            # Questo ISOLA le chiavi di sessione e risolve la race condition.
            thread_identity = f"{self.identity}_{host}:{port}_{secrets.token_hex(2)}"
            key_manager = SecureKeyManager(thread_identity)
            received_messages_queue: deque[str] = deque(maxlen=MAX_RECEIVED_MESSAGES) 
            protocol = SecureProtocol(key_manager, received_messages_queue)
            # 🟢 FINE MODIFICA
            
            # 0. Controllo limite connessioni (DoS - Circuit breaker)
            if self._connection_counter > MAX_GLOBAL_CONNECTIONS:
                logger.error(f"Global connection limit reached ({MAX_GLOBAL_CONNECTIONS}). Closing connection from {host}.")
                conn.close() # USA conn
                return # 'finally' si occuperà del decremento

            # 1. Handshake e autenticazione
            # 🟢 MODIFICA: Passa il key_manager locale
            if not self._perform_secure_handshake(conn, host, key_manager):
                logger.error(f"[{thread_name}] Handshake failed. Closing connection.")
                return # 'finally' si occuperà del decremento
            
            # 2. Loop di comunicazione (State Machine)
            while self.running:
                
                # 2.1. Leggi e parsa il prossimo pacchetto
                # 🟢 MODIFICA: Passa il protocol locale
                pkt_type, payload, offset = self._read_and_parse_packet(conn, host, protocol)

                # 2.2. Gestione Pacchetti JSON (Comandi)
                if pkt_type == 'json':
                    msg_type = payload.get('type')
                    logger.info(f"[{thread_name}] Received JSON command: {msg_type}")
                    
                    if msg_type == 'ping':
                        logger.info(f"[{thread_name}] Responding with PONG.")
                        try:
                            # 🟢 MODIFICA: Usa il protocol locale
                            pong_packet = protocol._create_json_packet('pong', {})
                            conn.sendall(pong_packet) # USA conn
                        except Exception as e:
                            logger.error(f"[{thread_name}] Failed to send PONG: {e}")
                            break # Interrompi se l'invio fallisce
                    
                    elif msg_type == 'file_header':
                        # 🟢 MODIFICA: Usa il protocol locale
                        filename = protocol.sanitize_filename(payload['payload']['filename'])
                        total_size = int(payload['payload']['total_size'])
                        safe_path = OUTPUT_DIR / filename
                        
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
                            else: # File locale corrotto/più grande
                                logger.warning(f"[{thread_name}] Local file {filename} is larger than expected ({current_offset} > {total_size}). Overwriting.")
                                current_offset = 0
                        
                        file_handle = safe_path.open(mode)
                        current_transfer = {'path': safe_path, 'handle': file_handle, 'total': total_size}
                        
                        # Invia ACK con l'offset
                        # 🟢 MODIFICA: Usa il protocol locale
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
                        
                        # Invia ACK finale
                        # 🟢 MODIFICA: Usa il protocol locale
                        ack_packet = protocol._create_json_packet('file_ack', {'filename': filename})
                        conn.sendall(ack_packet) # USA conn
                        current_transfer = {}

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

        # 🟢 CORREZIONE: Gestione pulita della disconnessione
        except ConnectionAbortedError as e:
            # Il client si è disconnesso (normale, dopo il file_ack o timeout)
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
            
            # 🟢 MODIFICA: Pulizia sicura delle chiavi locali del thread
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
    # 🟢 FINE REFACTORING THREAD-SAFE (Funzione #4)

    def start_server(self):
        """Avvia server sicuro"""
        self.running = True
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Permette il riuso dell'indirizzo
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        # 🟢 MODIFICA: Bindando a self.port (che può essere 0)
        self.socket.bind((self.host, self.port))
        
        # 🟢 MODIFICA: Recupera la porta reale assegnata dal SO
        # Se self.port era 0, ora conterrà la porta effimera
        actual_port = self.socket.getsockname()[1]
        self.port = actual_port
        
        self.socket.listen(5) # Backlog limitato
        
        # Il log ora mostrerà la porta corretta
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
            
            # 🟢 INIZIO REFACTORING THREAD-SAFE (Client)
            # Handshake (NON passa istanze, usa il fallback a self.*)
            if not self._perform_secure_handshake(self.peer_socket, self.peer_address):
                raise ConnectionRefusedError("Secure handshake failed.")
            # 🟢 FINE REFACTORING THREAD-SAFE (Client)
                
            logger.info("Connection successful. Ready to send files.")
            # Non avvia un loop, resta in attesa di comandi (es. send_file)

        except (socket.error, ConnectionRefusedError) as e:
            logger.error(f"Connection failed: {e}")
            self.shutdown() # Chiude se l'handshake fallisce
            raise # Rilancia l'eccezione

    def send_file(self, local_filepath: str, progress_callback: Optional[callable] = None):
        """Invia un file al server connesso (LOGICA CLIENT)"""
        if not self.running or not self.peer_socket:
            raise ConnectionError("Not connected to server.")
        
        local_path = Path(local_filepath)
        if not local_path.exists() or not local_path.is_file():
            raise FileNotFoundError(f"File not found: {local_filepath}")
        
        try:
            total_size = local_path.stat().st_size
            # 🟢 MODIFICA: Usa self.protocol (logica Client)
            filename = self.protocol.sanitize_filename(local_path.name)
            
            # 1. Invia 'file_header'
            logger.info(f"Sending file header for {filename} ({total_size} bytes)")
            header_payload = {'filename': filename, 'total_size': total_size}
            # 🟢 MODIFICA: Usa self.protocol (logica Client)
            header_packet = self.protocol._create_json_packet('file_header', header_payload)
            self.peer_socket.sendall(header_packet)
            self.transfer_stats['sent'] += 1

            # 2. Attendi ACK/Resume
            # 🟢 INIZIO REFACTORING THREAD-SAFE (Client)
            # (NON passa istanze, usa il fallback a self.*)
            pkt_type, response, _ = self._read_and_parse_packet(self.peer_socket, self.peer_address)
            # 🟢 FINE REFACTORING THREAD-SAFE (Client)
            self.transfer_stats['received'] += 1
            
            if pkt_type != 'json' or response.get('type') != 'file_resume_ack':
                raise Exception(f"Server did not acknowledge file header. Got: {response.get('type')}")
                
            start_offset = response['payload'].get('offset', 0)
            if start_offset > total_size:
                logger.error(f"Server offset {start_offset} is larger than file size {total_size}. Aborting.")
                raise Exception("Invalid resume offset from server.")
            
            logger.info(f"Server ACK. Starting upload from offset: {start_offset}")

            # 3. Invia Chunks
            with local_path.open('rb') as f:
                f.seek(start_offset)
                current_offset = start_offset
                
                while self.running and current_offset < total_size:
                    # Legge un chunk
                    chunk = f.read(BUFFER_SIZE) 
                    if not chunk:
                        break
                    
                    # 🟢 MODIFICA: Usa self.protocol (logica Client)
                    data_packet = self.protocol._create_data_packet(chunk, current_offset)
                    self.peer_socket.sendall(data_packet)
                    self.transfer_stats['sent'] += 1
                    
                    current_offset += len(chunk)
                    
                    if progress_callback:
                        try:
                            # Esegui il callback
                            progress_callback(filename, current_offset, total_size)
                        except Exception as cb_e:
                            logger.warning(f"Progress callback failed: {cb_e}")
                
            if not self.running:
                logger.warning("Transfer interrupted during chunk sending.")
                return

            # 4. Invia 'file_complete'
            logger.info(f"File send complete for {filename}. Sending 'file_complete' message.")
            # 🟢 MODIFICA: Usa self.protocol (logica Client)
            complete_packet = self.protocol._create_json_packet(
                'file_complete', 
                {'filename': filename, 'total_size': total_size}
            )
            self.peer_socket.sendall(complete_packet)
            self.transfer_stats['sent'] += 1
            
            # 5. Attendi ACK finale
            # 🟢 INIZIO REFACTORING THREAD-SAFE (Client)
            # (NON passa istanze, usa il fallback a self.*)
            pkt_type, response, _ = self._read_and_parse_packet(self.peer_socket, self.peer_address)
            # 🟢 FINE REFACTORING THREAD-SAFE (Client)
            self.transfer_stats['received'] += 1
            if pkt_type == 'json' and response.get('type') == 'file_ack':
                logger.info(f"Server acknowledged file_complete for {filename}.")
            else:
                logger.warning(f"Did not receive final file_ack. Got: {response.get('type')}")

        except Exception as e:
            logger.error(f"Error during send_file: {e}", exc_info=True)
            self.transfer_stats['errors'] += 1
            raise # Rilancia l'eccezione

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
        # 🟢 NOTA: Questo ora pulisce solo le chiavi del CLIENT
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
    parser = argparse.ArgumentParser(description="Secure File Transfer Node (v2.3)")
    parser.add_argument('--mode', choices=['server', 'client'], required=True, help='Run as server or client')
    parser.add_argument('--host', type=str, default='0.0.0.0', help='Binding host IP for server')
    parser.add_argument('--port', type=int, default=DEFAULT_PORT, help='Port number')
    parser.add_argument('--connect', type=str, help='Server IP:Port to connect (client mode)')
    parser.add_argument('--file', type=str, help='Path to the file to send (client mode)')
    
    args = parser.parse_args()
    
    node = SecureFileTransferNode(args.mode, args.host, args.port)
    
    try:
        if args.mode == 'server':
            node.start_server()
        else:
            # Modalità Client
            if not args.connect:
                print("[ERROR] Specify --connect SERVER_IP:PORT for client mode")
                return
            if not args.file:
                print("[ERROR] Specify --file LOCAL_FILE_PATH for client mode")
                return
            
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
            
            # Esegui la logica client
            try:
                node.connect_to_server(server_host, server_port)
                node.send_file(args.file, progress_callback=simple_progress_callback)
            except (ConnectionRefusedError, FileNotFoundError, Exception) as e:
                logger.error(f"Client operation failed: {e}")
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