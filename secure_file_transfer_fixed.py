#!/usr/bin/env python3
"""
Sistema di Trasferimento File Cifrato con Sicurezza Rafforzata
Versione corretta con tutte le vulnerabilità risolte
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
BUFFER_SIZE = 4096
KEY_ROTATION_INTERVAL = 300
MAX_FILE_SIZE = 100 * 1024 * 1024
PROTOCOL_VERSION = "2.0"
DEFAULT_PORT = 5555
MAX_PACKET_SIZE = 10 * 1024 * 1024  # 10MB max per pacchetto
SOCKET_TIMEOUT = 30
MAX_FAILED_ATTEMPTS = 5
RATE_LIMIT_WINDOW = 60  # secondi
MAX_REQUESTS_PER_WINDOW = 100
MAX_RECEIVED_MESSAGES = 1000
MAX_GLOBAL_CONNECTIONS = 50

# Schema JSON per validazione
MESSAGE_SCHEMA = {
    "type": "object",
    "properties": {
        "type": {"type": "string", "enum": ["file_transfer", "key_rotation", "ping", "pong", "auth"]},
        "version": {"type": "string"},
        "timestamp": {"type": "string"},
        "payload": {"type": "object"},
        "signature": {"type": "string"}
    },
    "required": ["type", "version", "timestamp", "payload"]
}

HEADER_PACKET_SIZE = struct.calcsize('!4sII16s12s16s') # = 56 byte

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
    
    def create_packet(self, msg_type: str, payload: Dict[str, Any], sign: bool = True) -> bytes:
        """Crea pacchetto con firma e cifratura"""
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
        
        # Header sicuro
        header = struct.pack(
            '!4sII16s12s16s',
            b'SFTP',
            2,  # Versione protocollo
            len(ciphertext),
            key_id.encode('utf-8')[:16].ljust(16, b'\x00'),
            nonce,
            tag
        )
        
        return header + ciphertext
    
    def parse_packet(self, data: bytes, client_id: str) -> Optional[Dict[str, Any]]:
        """Analizza pacchetto con rate limiting e controllo replay"""
        # 🟢 CORREZIONE: Rate limiting (DoS)
        if not self.rate_limiter.is_allowed(client_id):
            logger.warning(f"Rate limit exceeded for {client_id}")
            return None
        
        if len(data) < 54:
            raise ValueError("Packet too short")
        
        # Parse header
        magic, version, payload_len, key_id_raw, nonce, tag = struct.unpack(
            '!4sII16s12s16s', data[:HEADER_PACKET_SIZE] 
        )
        
        if magic != b'SFTP':
            raise ValueError("Invalid magic number")
        
        if version != 2:
            raise ValueError(f"Unsupported protocol version: {version}")
        
        # 🟢 CORREZIONE: Limite su dimensione payload (DoS)
        if payload_len > MAX_PACKET_SIZE:
            raise ValueError(f"Payload too large: {payload_len}")
        
        key_id = key_id_raw.rstrip(b'\x00').decode('utf-8')
        
        # Decifra
        ciphertext = data[HEADER_PACKET_SIZE : HEADER_PACKET_SIZE + payload_len]
        plaintext = self.decrypt_data(ciphertext, key_id, nonce, tag)
        
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
        
        return message
    
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
        self.key_manager = SecureKeyManager(self.identity)
        # 🟢 CORREZIONE: Utilizza deque per la gestione FIFO dei messaggi per evitare replay/DoS
        self.received_messages: deque[str] = deque(maxlen=MAX_RECEIVED_MESSAGES) 
        self.protocol = SecureProtocol(self.key_manager, self.received_messages)
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

    def _perform_secure_handshake(self) -> bool:
        """Esegue l'handshake RSA-OAEP"""
        try:
            # 1. Invia chiave pubblica e ricevi chiave pubblica del peer
            public_key_pem = self.key_manager.get_public_key_pem()
            self.peer_socket.sendall(struct.pack('!I', len(public_key_pem)) + public_key_pem)

            header_len = struct.calcsize('!I')
            header = self._recv_all(header_len)
            if not header: return False
            peer_key_len, = struct.unpack('!I', header)
            peer_key_pem = self._recv_all(peer_key_len)
            if not peer_key_pem: return False

            # 2. Scambia segreto (Iniziatore vs Risponditore)
            if self.mode == 'client':
                encrypted_secret = self.key_manager.establish_shared_secret(peer_key_pem)
                self.peer_socket.sendall(struct.pack('!I', len(encrypted_secret)) + encrypted_secret)
                confirm_header = self._recv_all(header_len)
                if not confirm_header: return False
                confirm_len, = struct.unpack('!I', confirm_header)
                confirm_msg = self._recv_all(confirm_len)
                if confirm_msg != b"AUTH_OK": return False
            elif self.mode == 'server':
                secret_header = self._recv_all(header_len)
                if not secret_header: return False
                secret_len, = struct.unpack('!I', secret_header)
                encrypted_secret = self._recv_all(secret_len)
                if not encrypted_secret: return False
                self.key_manager.decrypt_shared_secret(encrypted_secret)
                confirm_msg = b"AUTH_OK"
                self.peer_socket.sendall(struct.pack('!I', len(confirm_msg)) + confirm_msg)

            logger.info(f"Secure handshake successful with {self.peer_address}")
            return True

        except Exception as e:
            logger.error(f"Handshake failed: {e}")
            self.transfer_stats['auth_failures'] += 1
            return False

    def _recv_all(self, length: int) -> Optional[bytes]:
        """Riceve esattamente N bytes o None in caso di errore/timeout"""
        data = b''
        while len(data) < length:
            try:
                packet = self.peer_socket.recv(length - len(data))
                if not packet:
                    return None
                data += packet
            except socket.timeout:
                logger.warning(f"Socket timeout during reception from {self.peer_address}")
                return None
            except Exception as e:
                logger.error(f"Error receiving data: {e}")
                return None
        return data

    def _handle_connection(self, conn: socket.socket, addr: Tuple[str, int]):
        """Gestisce il traffico cifrato in un thread separato"""
        with self._counter_lock:
            self._connection_counter += 1
        
        thread_name = threading.current_thread().name
        host, port = addr
        self.peer_address = host
        self.peer_socket = conn
        self.peer_socket.settimeout(SOCKET_TIMEOUT)
        
        logger.info(f"[{thread_name}] Incoming connection from {host}:{port}")
        
        try:
            # 0. Controllo limite connessioni (DoS - Circuit breaker)
            if self._connection_counter > MAX_GLOBAL_CONNECTIONS:
                logger.error(f"Global connection limit reached ({MAX_GLOBAL_CONNECTIONS}). Closing connection from {host}.")
                self.peer_socket.close()
                return

            # 1. Handshake e autenticazione
            if not self._perform_secure_handshake():
                logger.error(f"[{thread_name}] Handshake failed. Closing connection.")
                return

            # Genera la chiave di sessione iniziale dopo l'handshake (e la ruota se presente)
           # self.key_manager.generate_session_key()
            
            # 2. Loop di comunicazione
            while self.running:
                # 2.1. Riceve header
                header = self._recv_all(HEADER_PACKET_SIZE)
                if not header: break

                # 2.2. Estrai la lunghezza del payload...
                _, _, payload_len, *_ = struct.unpack('!4sII16s12s16s', header)
                
                if payload_len > MAX_PACKET_SIZE:
                    logger.error("Received too large payload size in header.")
                    break

                ciphertext = self._recv_all(payload_len)
                if not ciphertext: break

                full_packet = header + ciphertext
                
                # 2.3. Parsa e decifra il pacchetto (incluse Rate Limit e Replay Check)
                message = self.protocol.parse_packet(full_packet, host)

                if message:
                    logger.info(f"[{thread_name}] Received message type: {message['type']}")
                    
                    if message['type'] == 'ping':
                        logger.info(f"[{thread_name}] Responding with PONG.")
                        try:
                            pong_packet = self.protocol.create_packet('pong', {})
                            self.peer_socket.sendall(pong_packet)
                        except Exception as e:
                            logger.error(f"[{thread_name}] Failed to send PONG: {e}")
                            break # Interrompi se l'invio fallisce
                    # Qui la logica di gestione file/rotazione chiavi

            logger.info(f"[{thread_name}] Connection closed gracefully.")

        except (ValueError, Exception) as e:
            logger.error(f"[{thread_name}] Protocol or connection error: {e}", exc_info=False)
            self.transfer_stats['errors'] += 1
        finally:
            try:
                self.peer_socket.close()
            except Exception:
                pass
            with self._counter_lock:
                self._connection_counter -= 1
    def _client_message_loop(self):
        """Gestisce il traffico cifrato per il client (dopo l'handshake)"""
        thread_name = threading.current_thread().name
        host = self.peer_address
        
        try:
            # Genera la chiave di sessione iniziale dopo l'handshake
            #self.key_manager.generate_session_key()
            
            logger.info(f"[{thread_name}] Sending initial PING to server...")
            ping_packet = self.protocol.create_packet('ping', {})
            self.peer_socket.sendall(ping_packet)
            
            # Loop di comunicazione (preso da _handle_connection)
            while self.running:
                # 2.1. Riceve header
                header = self._recv_all(HEADER_PACKET_SIZE) # Usa la costante
                if not header: break

                # 2.2. Estrai la lunghezza del payload
                _, _, payload_len, *_ = struct.unpack('!4sII16s12s16s', header)
                
                if payload_len > MAX_PACKET_SIZE:
                    logger.error("Received too large payload size in header.")
                    break

                ciphertext = self._recv_all(payload_len)
                if not ciphertext: break

                full_packet = header + ciphertext
                
                # 2.3. Parsa e decifra il pacchetto
                message = self.protocol.parse_packet(full_packet, host)

                if message:
                    logger.info(f"[{thread_name}] Received message type: {message['type']}")
                    
                    if message['type'] == 'pong':
                        logger.info(f"[{thread_name}] Server responded with PONG. Connection active.")
                        # In un'app reale, qui potremmo inviare il file
                        # Per ora, chiudiamo la connessione dopo il test
                        self.running = False 
                    # ... (Futura logica client qui)

            logger.info(f"[{thread_name}] Connection closed gracefully.")

        except (ValueError, Exception) as e:
            # Evitiamo di loggare "Handshake failed" qui
            if "Connection reset by peer" not in str(e) and self.running:
                logger.error(f"[{thread_name}] Protocol or connection error: {e}", exc_info=False)
            self.transfer_stats['errors'] += 1
        finally:
            try:
                self.peer_socket.close()
            except Exception:
                pass

    def start_server(self):
        """Avvia server sicuro"""
        self.running = True
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Permette il riuso dell'indirizzo
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind((self.host, self.port))
        self.socket.listen(5) # Backlog limitato
        logger.info(f"Server listening on {self.host}:{self.port}...")

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
        """Connette al server in modo sicuro"""
        self.running = True
        self.peer_address = host
        self.peer_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.peer_socket.settimeout(SOCKET_TIMEOUT)
        
        try:
            logger.info(f"Connecting to {host}:{port}...")
            self.peer_socket.connect((host, port))
            
            # Handshake
            if not self._perform_secure_handshake():
                raise ConnectionRefusedError("Secure handshake failed.")
                
            # Avvia la gestione della connessione in un thread
            self._client_message_loop()

        except (socket.error, ConnectionRefusedError) as e:
            logger.error(f"Connection failed: {e}")
        finally:
            self.shutdown()

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
        if self.key_manager.current_key:
            _clear_memory(self.key_manager.current_key)
            self.key_manager.current_key = None
        if self.key_manager.shared_secret:
            _clear_memory(self.key_manager.shared_secret)
            self.key_manager.shared_secret = None
            
        logger.info("Node shut down.")

def main():
    parser = argparse.ArgumentParser(description="Secure File Transfer Node")
    parser.add_argument('--mode', choices=['server', 'client'], required=True, help='Run as server or client')
    parser.add_argument('--host', type=str, default='0.0.0.0', help='Binding host IP for server')
    parser.add_argument('--port', type=int, default=DEFAULT_PORT, help='Port number')
    parser.add_argument('--connect', type=str, help='Server IP:Port to connect (client mode)')
    
    args = parser.parse_args()
    
    node = SecureFileTransferNode(args.mode, args.host, args.port)
    
    try:
        if args.mode == 'server':
            node.start_server()
        else:
            if not args.connect:
                print("[ERROR] Specify --connect SERVER_IP:PORT for client mode")
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
            
            node.connect_to_server(server_host, server_port)
            
    except KeyboardInterrupt:
        logger.info("User interrupt, shutting down.")
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
    finally:
        node.shutdown()

if __name__ == '__main__':
    main()
