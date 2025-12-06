# Proxy Testing Guide

Guida completa per testare il supporto proxy di SFT con SOCKS4, SOCKS5 e HTTP proxy in ambiente locale.

## Prerequisiti

```bash
# Installa gli strumenti necessari
sudo apt update
sudo apt install -y dante-server privoxy ssh

# Verifica installazione Python e dipendenze SFT
cd /home/vmbox/SFT
source .venv/bin/activate
pip install -r requirements.txt
```

## Setup 1: SOCKS5 Proxy (con Dante)

### Configurazione Dante Server

Crea il file di configurazione per Dante:

```bash
sudo tee /etc/danted.conf > /dev/null <<'EOF'
logoutput: syslog /var/log/danted.log

internal: 127.0.0.1 port = 1080
external: 127.0.0.1

clientmethod: none
socksmethod: none

client pass {
    from: 127.0.0.0/8 to: 0.0.0.0/0
    log: error
}

socks pass {
    from: 127.0.0.0/8 to: 0.0.0.0/0
    protocol: tcp udp
    log: error
}
EOF
```

### Avvia il proxy SOCKS5

```bash
# Avvia Dante in foreground per vedere i log
sudo danted -f /etc/danted.conf -D

# Oppure in background
sudo systemctl restart danted
sudo systemctl status danted
```

### Test del proxy SOCKS5

Terminale 1 - Avvia il server SFT:
```bash
cd /home/vmbox/SFT
source .venv/bin/activate
python3 sft.py --mode server --host 127.0.0.1 --port 5555
```

Terminale 2 - Crea un file di test e trasferisci tramite proxy:
```bash
cd /home/vmbox/SFT
source .venv/bin/activate

# Crea file di test
echo "Test SOCKS5 proxy transfer" > test_socks5.txt

# Trasferisci tramite SOCKS5
python3 sft.py --mode client \
    --connect 127.0.0.1:5555 \
    --file test_socks5.txt \
    --proxy-type socks5 \
    --proxy-host 127.0.0.1 \
    --proxy-port 1080
```

### Verifica risultato

```bash
# Verifica che il file sia stato ricevuto
ls -lh ricevuti/
cat ricevuti/test_socks5.txt
```

---

## Setup 2: SOCKS5 Proxy con Autenticazione (SSH Tunnel)

### Crea tunnel SSH come proxy SOCKS5

```bash
# Avvia SSH in locale con SOCKS5 proxy (porta 1081)
ssh -D 1081 -N -f localhost

# Verifica che il tunnel sia attivo
netstat -tlnp | grep 1081
```

### Test con SSH tunnel

Terminale 1 - Server (se non gia attivo):
```bash
cd /home/vmbox/SFT
source .venv/bin/activate
python3 sft.py --mode server --host 127.0.0.1 --port 5555
```

Terminale 2 - Client con SSH tunnel:
```bash
cd /home/vmbox/SFT
source .venv/bin/activate

# Crea file di test
echo "Test SSH SOCKS5 tunnel" > test_ssh_socks5.txt

# Trasferisci tramite SSH tunnel
python3 sft.py --mode client \
    --connect 127.0.0.1:5555 \
    --file test_ssh_socks5.txt \
    --proxy-type socks5 \
    --proxy-host 127.0.0.1 \
    --proxy-port 1081
```

---

## Setup 3: HTTP Proxy (con Privoxy)

### Configurazione Privoxy

Modifica la configurazione di Privoxy:

```bash
# Backup configurazione originale
sudo cp /etc/privoxy/config /etc/privoxy/config.bak

# Configura Privoxy per ascoltare su localhost:8118
sudo tee -a /etc/privoxy/config > /dev/null <<'EOF'

# Listen address
listen-address  127.0.0.1:8118

# Enable logging
logfile logfile

# Allow all connections from localhost
accept-intercepted-requests 1
EOF
```

### Avvia Privoxy

```bash
# Riavvia Privoxy
sudo systemctl restart privoxy
sudo systemctl status privoxy

# Verifica che sia in ascolto
netstat -tlnp | grep 8118
```

### Test del proxy HTTP

Terminale 1 - Server (se non gia attivo):
```bash
cd /home/vmbox/SFT
source .venv/bin/activate
python3 sft.py --mode server --host 127.0.0.1 --port 5555
```

Terminale 2 - Client con HTTP proxy:
```bash
cd /home/vmbox/SFT
source .venv/bin/activate

# Crea file di test
echo "Test HTTP proxy transfer" > test_http_proxy.txt

# Trasferisci tramite HTTP proxy
python3 sft.py --mode client \
    --connect 127.0.0.1:5555 \
    --file test_http_proxy.txt \
    --proxy-type http \
    --proxy-host 127.0.0.1 \
    --proxy-port 8118
```

---

## Setup 4: SOCKS4 Proxy (con Dante configurato per SOCKS4)

### Configurazione Dante per SOCKS4

Crea una configurazione separata per SOCKS4:

```bash
sudo tee /etc/danted-socks4.conf > /dev/null <<'EOF'
logoutput: syslog /var/log/danted-socks4.log

internal: 127.0.0.1 port = 1082
external: 127.0.0.1

clientmethod: none
socksmethod: username

client pass {
    from: 127.0.0.0/8 to: 0.0.0.0/0
    log: error
}

socks pass {
    from: 127.0.0.0/8 to: 0.0.0.0/0
    protocol: tcp
    log: error
}
EOF
```

### Avvia proxy SOCKS4

```bash
# Avvia Dante per SOCKS4 su porta 1082
sudo danted -f /etc/danted-socks4.conf -D
```

### Test del proxy SOCKS4

Terminale 1 - Server (se non gia attivo):
```bash
cd /home/vmbox/SFT
source .venv/bin/activate
python3 sft.py --mode server --host 127.0.0.1 --port 5555
```

Terminale 2 - Client con SOCKS4:
```bash
cd /home/vmbox/SFT
source .venv/bin/activate

# Crea file di test
echo "Test SOCKS4 proxy transfer" > test_socks4.txt

# Trasferisci tramite SOCKS4
python3 sft.py --mode client \
    --connect 127.0.0.1:5555 \
    --file test_socks4.txt \
    --proxy-type socks4 \
    --proxy-host 127.0.0.1 \
    --proxy-port 1082
```

---

## Test Avanzati

### Test Download tramite Proxy

```bash
# Server
python3 sft.py --mode server --host 127.0.0.1 --port 5555

# Client - Lista file tramite proxy
python3 sft.py --mode client \
    --connect 127.0.0.1:5555 \
    --list \
    --proxy-type socks5 \
    --proxy-host 127.0.0.1 \
    --proxy-port 1080

# Client - Download tramite proxy
python3 sft.py --mode client \
    --connect 127.0.0.1:5555 \
    --download test_socks5.txt \
    --output ./downloaded/ \
    --proxy-type socks5 \
    --proxy-host 127.0.0.1 \
    --proxy-port 1080
```

### Test con File Grandi

```bash
# Crea file di test da 100MB
dd if=/dev/urandom of=test_large.bin bs=1M count=100

# Upload tramite proxy
python3 sft.py --mode client \
    --connect 127.0.0.1:5555 \
    --file test_large.bin \
    --proxy-type socks5 \
    --proxy-host 127.0.0.1 \
    --proxy-port 1080
```

### Test Interruzione e Resume

```bash
# Avvia trasferimento
python3 sft.py --mode client \
    --connect 127.0.0.1:5555 \
    --file test_large.bin \
    --proxy-type http \
    --proxy-host 127.0.0.1 \
    --proxy-port 8118

# Interrompi con Ctrl+C durante il trasferimento

# Riprendi il trasferimento
python3 sft.py --mode client \
    --connect 127.0.0.1:5555 \
    --file test_large.bin \
    --proxy-type http \
    --proxy-host 127.0.0.1 \
    --proxy-port 8118
```

---

## Troubleshooting

### Verifica connettivita proxy

```bash
# Test SOCKS5
curl --socks5 127.0.0.1:1080 http://example.com

# Test HTTP proxy
curl --proxy http://127.0.0.1:8118 http://example.com

# Verifica porte in ascolto
sudo netstat -tlnp | grep -E '1080|1081|1082|8118'
```

### Log del proxy

```bash
# Log Dante SOCKS5
sudo tail -f /var/log/danted.log

# Log Privoxy HTTP
sudo tail -f /var/log/privoxy/logfile

# Log SFT
tail -f secure_transfer.log
```

### Problemi comuni

1. **Proxy non raggiungibile**
   - Verifica che il proxy sia in ascolto: `netstat -tlnp | grep <porta>`
   - Controlla i firewall: `sudo ufw status`

2. **Autenticazione fallita**
   - SOCKS4 supporta solo username, non password
   - Verifica credenziali per SOCKS5/HTTP autenticati

3. **Timeout connessione**
   - Aumenta timeout del socket nel codice se necessario
   - Verifica che il server SFT sia raggiungibile dal proxy

4. **Errore "Proxy initialization failed"**
   - Verifica tipo proxy corretto (socks4/socks5/http)
   - Verifica porta corretta (1-65535)
   - Controlla log del proxy per dettagli

---

## Cleanup

```bash
# Ferma tutti i servizi
sudo systemctl stop danted
sudo systemctl stop privoxy
pkill -f "ssh -D"

# Rimuovi file di test
rm -f test_*.txt test_*.bin
rm -f ricevuti/test_*

# Ripristina configurazioni
sudo cp /etc/privoxy/config.bak /etc/privoxy/config
```

---

## Riepilogo Porte

| Tipo Proxy | Porta | Autenticazione |
|------------|-------|----------------|
| SOCKS5 (Dante) | 1080 | No |
| SOCKS5 (SSH) | 1081 | Sistema |
| SOCKS4 (Dante) | 1082 | Username only |
| HTTP (Privoxy) | 8118 | No |
| Server SFT | 5555 | ECDH+Ed25519 |

---

## Note di Sicurezza

- Questi test sono per ambiente locale (127.0.0.1)
- Per ambienti di produzione, configurare autenticazione forte sui proxy
- Non esporre proxy non autenticati su interfacce pubbliche
- Considerare l'uso di TLS/SSL per proxy su reti non fidate
- Le credenziali proxy passate via CLI sono visibili nei processi
