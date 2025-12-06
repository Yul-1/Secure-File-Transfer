# Proxy Connection Troubleshooting Guide

## Connection Abort Error After Handshake

**Symptom:**
```
INFO - Secure handshake successful
INFO - Sending file header
ERROR - Connection closed while reading header
```

**Root Cause:**
The SOCKS5 proxy is working correctly, but the **target server is not running** or not reachable from the proxy.

## Diagnostic Steps

### 1. Verify Proxy is Running
```bash
netstat -tuln | grep 1081
# OR
ss -tuln | grep 1081

# Should show:
# tcp  0  0  127.0.0.1:1081  0.0.0.0:*  LISTEN
```

### 2. Verify Target Server is Running
```bash
ps aux | grep "sft.py.*server"
netstat -tuln | grep 5555

# Start server if missing:
python3 sft.py --mode server --port 5555
```

### 3. Test Direct Connection (No Proxy)
```bash
# Terminal 1: Start server
python3 sft.py --mode server --port 5555

# Terminal 2: Test without proxy
python3 sft.py --mode client --connect 127.0.0.1:5555 --file test.txt
```

### 4. Test Proxy Connection
```bash
# Only after direct connection works:
python3 sft.py --mode client --connect 127.0.0.1:5555 \
  --proxy-type socks5 --proxy-host 127.0.0.1 --proxy-port 1081 \
  --file test.txt
```

## Common Errors and Solutions

| Error Message | Cause | Solution |
|--------------|-------|----------|
| Connection refused | No server on target port | Start SFT server first |
| Proxy connection failed | Proxy not running | Start SOCKS5 proxy (e.g., ssh -D 1081) |
| Connection timeout | Firewall blocking | Check iptables/firewall rules |
| Peer closed connection | Server crashed during handshake | Check server logs |

## Network Architecture

```
[Client] --TLS--> [SOCKS5 Proxy @ :1081] --TLS--> [Server @ :5555]
   ^                      ^                            ^
   |                      |                            |
Works OK          Works OK (verified)         MISSING/NOT RUNNING
```

## Quick Start Test Sequence

```bash
# Step 1: Start SOCKS5 proxy
ssh -D 1081 -N localhost &

# Step 2: Verify proxy
curl --socks5 127.0.0.1:1081 http://example.com

# Step 3: Start SFT server
python3 sft.py --mode server --port 5555 &

# Step 4: Test direct
echo "test" > /tmp/test.txt
python3 sft.py --mode client --connect 127.0.0.1:5555 --file /tmp/test.txt

# Step 5: Test via proxy
python3 sft.py --mode client --connect 127.0.0.1:5555 \
  --proxy-type socks5 --proxy-host 127.0.0.1 --proxy-port 1081 \
  --file /tmp/test.txt
```

## Enhanced Error Logging

As of the latest update, the code now provides:
- Detailed socket error types (ConnectionReset vs Timeout vs Refused)
- Proxy-specific error messages with troubleshooting hints
- Byte-count tracking for partial reads

Check `secure_transfer.log` for diagnostic details.
