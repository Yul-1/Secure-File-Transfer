# AegisTransfer (SFT)

[![Python Version](https://img.shields.io/badge/python-3.9%2B-blue)](https://www.python.org/)
[![Build Status](https://img.shields.io/badge/build-passing-brightgreen)](https://github.com/Yul-1/SFT)
[![Security](https://img.shields.io/badge/security-hardened-blueviolet)](https://github.com/Yul-1/SFT)
[![License](https://img.shields.io/badge/license-MIT-green)](https://github.com/Yul-1/SFT/blob/main/LICENSE)

**AegisTransfer** è un sistema di trasferimento file sicuro (Secure File Transfer - SFT) client-server ad alte prestazioni. È progettato da zero con un'architettura "security-first", combinando la velocità della crittografia C (via OpenSSL) con la sicurezza e la flessibilità di Python.

[cite_start]Il sistema utilizza un modulo di accelerazione C per operazioni crittografiche intensive [cite: 133][cite_start], ma include un **fallback trasparente** a un'implementazione Python pura (`cryptography`) [cite: 3, 8] nel caso in cui il modulo C non sia compilato o non sia disponibile, garantendo la portabilità.

## Indice

1.  [Perché AegisTransfer?](#perché-aegistransfer)
2.  [Architettura del Sistema](#architettura-del-sistema)
3.  [Caratteristiche di Sicurezza](#caratteristiche-di-sicurezza-dettagliate)
4.  [Installazione e Build (Ubuntu/Debian)](#installazione-e-build-ubuntudebian)
5.  [Utilizzo](#utilizzo)
6.  [Roadmap (Sviluppo Futuro)](#roadmap-sviluppo-futuro)

## Perché AegisTransfer?

Mentre esistono protocolli come SCP o SFTP, questo progetto serve come studio approfondito sull'implementazione di software sicuro a più livelli. L'obiettivo primario è mitigare le vulnerabilità comuni a livello di protocollo, rete e implementazione.

* [cite_start]**Performance:** Le operazioni crittografiche (AES-GCM) sono delegate a C/OpenSSL compilato[cite: 146, 169], riducendo drasticamente il carico sulla CPU rispetto a Python puro.
* [cite_start]**Robustezza:** Il sistema è protetto contro attacchi DoS [cite: 49, 105][cite_start], replay attacks [cite: 87, 92] [cite_start]e timing attacks[cite: 31, 202].
* [cite_start]**Sicurezza della Memoria:** Particolare attenzione è data alla pulizia sicura dei dati sensibili (come chiavi e buffer) dalla memoria[cite: 4, 135, 167, 188].

## Architettura del Sistema

Il progetto è diviso in tre layer logici che interagiscono tra loro:

1.  **Livello Protocollo (Python) - `secure-file-transfer-fixed.txt`**
    È il "cervello" dell'applicazione. [cite_start]Gestisce la logica di rete (TCP server/client) [cite: 114][cite_start], implementa il protocollo di handshake (scambio di chiavi RSA-OAEP) [cite: 64, 95] e gestisce la logica di trasferimento. [cite_start]È responsabile dell'applicazione delle contromisure di sicurezza a livello di rete, come il rate-limiting [cite: 72] [cite_start]e la protezione anti-replay[cite: 92].

2.  **Livello Wrapper (Python) - `python-wrapper-fixed.txt`**
    È il "ponte" flessibile. [cite_start]Fornisce una classe `SecureCrypto` [cite: 7] che funge da API unificata per il resto dell'applicazione. [cite_start]Al momento dell'inizializzazione, tenta di importare il modulo C compilato (`crypto_accelerator`)[cite: 1]. [cite_start]In caso di fallimento (es. `ImportError`), attiva un flag e utilizza implementazioni di fallback pure-Python (usando la libreria `cryptography`) per tutte le operazioni[cite: 3, 25].

3.  **Livello Core (C) - `crypto-accelerator-fixed.txt`**
    È il "motore" ad alte prestazioni. [cite_start]Si tratta di un'estensione Python C [cite: 207] che espone funzioni OpenSSL ottimizzate. Gestisce le operazioni CPU-intensive:
    * [cite_start]Cifratura e Decifratura AES-256-GCM[cite: 146, 169].
    * [cite_start]Generazione di byte casuali sicuri (`RAND_bytes`)[cite: 143].
    * [cite_start]Confronto a tempo costante (`CRYPTO_memcmp`)[cite: 202].

## Caratteristiche di Sicurezza Dettagliate

Questo sistema implementa un'ampia gamma di contromisure di sicurezza:

### Crittografia e Autenticazione

* [cite_start]**Cifratura Dati (C):** AES-256-GCM tramite OpenSSL[cite: 154, 180].
* [cite_start]**Cifratura Dati (Fallback Python):** AES-256-GCM tramite `cryptography`[cite: 26, 30].
* [cite_start]**Handshake Sicuro:** Scambio di un segreto condiviso utilizzando RSA-4096 con padding OAEP (SHA-256)[cite: 64, 67].
* **Autenticazione Messaggi:**
    1.  [cite_start]**HMAC:** Tutti i pacchetti JSON sono firmati con HMAC-SHA256 [cite: 71, 89] [cite_start](la cui chiave è derivata dal segreto condiviso tramite PBKDF2 [cite: 69]).
    2.  [cite_start]**GCM Tag:** L'autenticità del ciphertext è garantita dal GCM Authentication Tag[cite: 26, 76].

### Protezione Denial of Service (DoS)

* [cite_start]**Rate Limiting:** Un `RateLimiter` [cite: 49] [cite_start]basato su client ID (IP) previene attacchi "brute force" o "spam" di pacchetti, bloccando richieste che superano una soglia definita[cite: 84].
* [cite_start]**Limite Connessioni Globale:** Il server limita il numero massimo di connessioni globali e thread attivi (`MAX_GLOBAL_CONNECTIONS`) [cite: 45, 118][cite_start], agendo come un *circuit breaker* per prevenire l'esaurimento delle risorse[cite: 105].
* **Validazione Dimensione Pacchetti:**
    * [cite_start]A livello di protocollo, la lunghezza del payload letta dall'header è validata contro `MAX_PACKET_SIZE` *prima* di allocare memoria[cite: 86, 109].
    * [cite_start]A livello C, tutti i buffer (plaintext, ciphertext) sono validati contro `MAX_BUFFER_SIZE` (10MB) per prevenire allocazioni eccessive[cite: 137, 151, 175].
* [cite_start]**Timeout Socket:** Tutti i socket hanno un timeout (`SOCKET_TIMEOUT`) [cite: 45] [cite_start]per prevenire attacchi "slowloris" o connessioni appese[cite: 102].

### Protezione Anti-Replay

* **Timestamp:** Ogni pacchetto include un timestamp. [cite_start]Il server rifiuta pacchetti con timestamp troppo vecchi (tolleranza di 5 minuti)[cite: 91].
* [cite_start]**Message ID Unici:** Il server mantiene una `deque` (una coda FIFO a dimensione fissa [cite: 94]) degli hash dei messaggi ricevuti. [cite_start]Se un hash viene ricevuto una seconda volta, è considerato un attacco replay e scartato[cite: 87, 92].

### Protezione Vulnerabilità Software

* **Timing Attacks:**
    * [cite_start]La verifica delle firme HMAC in Python usa `hmac.compare_digest`[cite: 31].
    * [cite_start]La verifica nel modulo C usa `CRYPTO_memcmp` di OpenSSL[cite: 202]. Entrambe sono funzioni a tempo costante.
* **Gestione Sicura della Memoria:**
    * [cite_start]Il modulo C utilizza `secure_memzero` (o `explicit_bzero` se disponibile) [cite: 135] [cite_start]per cancellare chiavi, IV e buffer di plaintext/ciphertext *dopo l'uso*[cite: 167, 188].
    * [cite_start]Il wrapper Python usa una funzione `_clear_memory` [cite: 4, 46] [cite_start]per cancellare (best-effort) le chiavi dalla memoria (es. nella cache LRU [cite: 19, 22] [cite_start]e durante lo shutdown [cite: 125]).
* [cite_start]**Hardening di Compilazione:** Il modulo C è compilato (su Linux) con flag di sicurezza moderni per mitigare buffer overflow e altre vulnerabilità a livello binario (`-fstack-protector-strong`, `-D_FORTIFY_SOURCE=2`, `-Wl,-z,relro,-z,now`)[cite: 33].
* [cite_start]**Path Traversal:** I nomi dei file ricevuti sono rigorosamente sanitizzati (rimozione di `..`, caratteri speciali, ecc.) prima di qualsiasi operazione su disco[cite: 72, 73].

## Installazione e Build (Ubuntu/Debian)

Questo progetto richiede `python3-dev` (per gli header CPython), `build-essential` (per GCC) e `libssl-dev` (per gli header OpenSSL).

1.  **Clona il Repository:**
    ```bash
    git clone [https://github.com/Yul-1/SFT.git](https://github.com/Yul-1/SFT.git)
    cd SFT
    ```

2.  **Installa Dipendenze di Sistema e Python:**
    ```bash
    # Dipendenze per la compilazione C
    sudo apt update
    sudo apt install -y python3-dev build-essential libssl-dev python3-pip

    # Dipendenze Python (per fallback e validazione)
    pip install cryptography jsonschema
    ```

3.  **Compila il Modulo C:**
    Il wrapper Python include un comodo script di compilazione.
    ```bash
    python3 python-wrapper-fixed.py --compile
    ```
    Se l'operazione ha successo, vedrai: `✓ C module compiled successfully as crypto_accelerator.so`

4.  **Verifica (Test Locale):**
    Esegui i test di integrazione del wrapper. Questo verificherà che il modulo C sia caricato correttamente E che il fallback Python funzioni.
    ```bash
    python3 python-wrapper-fixed.py --test
    ```

## Utilizzo

### 🖥️ Avviare il Server

Il server si mette in ascolto sull'host e la porta specificati (default: `0.0.0.0:5555`).

```bash
# Esegui sull'host locale, porta 5555
python3 secure-file-transfer-fixed.py --mode server

# Esegui su un IP specifico e porta custom
python3 secure-file-transfer-fixed.py --mode server --host 192.168.1.100 --port 9999
```
Il server loggherà: `Server listening on 0.0.0.0:5555...`

### 💻 Connettere il Client

Il client richiede il flag `--connect` per specificare l'indirizzo del server.

```bash
# Connettiti a un server locale
python3 secure-file-transfer-fixed.py --mode client --connect 127.0.0.1:5555

# Connettiti a un server remoto
python3 secure-file-transfer-fixed.py --mode client --connect 192.168.1.100:9999
```
Se l'handshake ha successo, entrambi i lati loggheranno: `Secure handshake successful with ...`

## Roadmap (Sviluppo Futuro)

Questo repository implementa un'architettura di connessione sicura e autenticata. La prossima fase si concentrerà sull'implementazione della logica di trasferimento file.

* [cite_start]**Team Dev:** Implementare la logica `file_transfer` nel loop `_handle_connection` [cite: 112] per gestire l'invio e la ricezione di file reali.
* **Team Dev:** Aggiungere la ripresa dei trasferimenti interrotti.
* **Team Controllo:** Scrivere un set di test `pytest` completo per automatizzare i test di integrazione, inclusi i fallimenti (es. tag GCM errati, firme HMAC non valide, test del rate-limit).
* [cite_start]**Team Porting:** Adattare gli script di compilazione C e le dipendenze (es. `secure_memzero` [cite: 133][cite_start], `RAND_seed` [cite: 209]) per Windows (MSVC) e macOS (Clang).