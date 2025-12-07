#!/usr/bin/env python3
"""
Proxy Connection Diagnostic Tool for SFT
Tests SOCKS5 proxy connectivity and target server reachability
"""

import socket
import sys
import argparse

try:
    import socks
except ModuleNotFoundError:
    print("[ERROR] PySocks module not found. Install: pip install PySocks")
    sys.exit(1)

def test_direct_connection(host: str, port: int, timeout: int = 5) -> bool:
    """Test direct TCP connection to target"""
    print(f"\n[1/4] Testing direct connection to {host}:{port}...")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        sock.close()
        print(f"  [OK] Direct connection successful")
        return True
    except ConnectionRefusedError:
        print(f"  [FAIL] Connection refused - no server listening on {host}:{port}")
        return False
    except socket.timeout:
        print(f"  [FAIL] Connection timeout after {timeout}s")
        return False
    except Exception as e:
        print(f"  [FAIL] {type(e).__name__}: {e}")
        return False

def test_proxy_reachable(proxy_host: str, proxy_port: int, timeout: int = 5) -> bool:
    """Test if proxy server is reachable"""
    print(f"\n[2/4] Testing proxy reachability at {proxy_host}:{proxy_port}...")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((proxy_host, proxy_port))
        sock.close()
        print(f"  [OK] Proxy is reachable")
        return True
    except ConnectionRefusedError:
        print(f"  [FAIL] Proxy connection refused - no proxy on {proxy_host}:{proxy_port}")
        return False
    except socket.timeout:
        print(f"  [FAIL] Proxy timeout after {timeout}s")
        return False
    except Exception as e:
        print(f"  [FAIL] {type(e).__name__}: {e}")
        return False

def test_proxy_connection(proxy_host: str, proxy_port: int, target_host: str, target_port: int, timeout: int = 5) -> bool:
    """Test SOCKS5 proxy connection to target"""
    print(f"\n[3/4] Testing SOCKS5 proxy connection to {target_host}:{target_port}...")
    try:
        sock = socks.socksocket()
        sock.set_proxy(socks.SOCKS5, proxy_host, proxy_port)
        sock.settimeout(timeout)
        sock.connect((target_host, target_port))
        sock.close()
        print(f"  [OK] Proxy connection successful")
        return True
    except socks.ProxyConnectionError as e:
        print(f"  [FAIL] Proxy failed to reach target: {e}")
        print(f"         Likely cause: No server running on {target_host}:{target_port}")
        return False
    except socks.GeneralProxyError as e:
        print(f"  [FAIL] SOCKS5 proxy error: {e}")
        return False
    except socket.timeout:
        print(f"  [FAIL] Connection timeout through proxy after {timeout}s")
        return False
    except Exception as e:
        print(f"  [FAIL] {type(e).__name__}: {e}")
        return False

def test_sft_handshake(proxy_host: str, proxy_port: int, target_host: str, target_port: int) -> bool:
    """Test if SFT server responds to connection"""
    print(f"\n[4/4] Testing SFT server handshake via proxy...")
    try:
        sock = socks.socksocket()
        sock.set_proxy(socks.SOCKS5, proxy_host, proxy_port)
        sock.settimeout(10)
        sock.connect((target_host, target_port))

        # Try to receive initial handshake data (X25519 key exchange)
        data = sock.recv(4, socket.MSG_PEEK)
        if len(data) > 0:
            print(f"  [OK] SFT server is responding (received {len(data)} bytes)")
            sock.close()
            return True
        else:
            print(f"  [WARN] Connection established but no data received")
            sock.close()
            return False
    except Exception as e:
        print(f"  [FAIL] Handshake test failed: {e}")
        return False

def main():
    parser = argparse.ArgumentParser(description="SFT Proxy Connection Diagnostic Tool")
    parser.add_argument('--target-host', default='127.0.0.1', help='Target server IP (default: 127.0.0.1)')
    parser.add_argument('--target-port', type=int, default=5555, help='Target server port (default: 5555)')
    parser.add_argument('--proxy-host', default='127.0.0.1', help='SOCKS5 proxy IP (default: 127.0.0.1)')
    parser.add_argument('--proxy-port', type=int, default=1081, help='SOCKS5 proxy port (default: 1081)')
    parser.add_argument('--skip-direct', action='store_true', help='Skip direct connection test')

    args = parser.parse_args()

    print("=" * 70)
    print("SFT Proxy Connection Diagnostic Tool")
    print("=" * 70)
    print(f"Target Server: {args.target_host}:{args.target_port}")
    print(f"SOCKS5 Proxy:  {args.proxy_host}:{args.proxy_port}")

    results = []

    if not args.skip_direct:
        results.append(("Direct Connection", test_direct_connection(args.target_host, args.target_port)))

    results.append(("Proxy Reachable", test_proxy_reachable(args.proxy_host, args.proxy_port)))
    results.append(("Proxy Connection", test_proxy_connection(args.proxy_host, args.proxy_port, args.target_host, args.target_port)))

    # Only test handshake if proxy connection succeeded
    if results[-1][1]:
        results.append(("SFT Handshake", test_sft_handshake(args.proxy_host, args.proxy_port, args.target_host, args.target_port)))

    print("\n" + "=" * 70)
    print("DIAGNOSTIC SUMMARY")
    print("=" * 70)

    for test_name, result in results:
        status = "PASS" if result else "FAIL"
        print(f"  {test_name:25} [{status}]")

    print("\n" + "=" * 70)

    # Provide recommendations
    all_pass = all(r[1] for r in results)
    if all_pass:
        print("\n[SUCCESS] All tests passed. Your proxy configuration is working correctly.")
        print(f"\nYou can now use:")
        print(f"  python3 sft.py --mode client --connect {args.target_host}:{args.target_port} \\")
        print(f"    --proxy-type socks5 --proxy-host {args.proxy_host} --proxy-port {args.proxy_port} \\")
        print(f"    --file yourfile.txt")
    else:
        print("\n[FAILURE] Some tests failed. Troubleshooting steps:")

        if not args.skip_direct and not results[0][1]:
            print(f"\n  1. Start the SFT server:")
            print(f"     python3 sft.py --mode server --port {args.target_port}")

        if len(results) > 1 and not results[1][1]:
            print(f"\n  2. Start your SOCKS5 proxy:")
            print(f"     ssh -D {args.proxy_port} -N localhost")

        if len(results) > 2 and not results[2][1]:
            print(f"\n  3. Verify firewall rules allow proxy->target connection")
            print(f"     Check iptables/firewall settings")

        print(f"\n  See PROXY_TROUBLESHOOTING.md for detailed guidance.")

    print("=" * 70)

    sys.exit(0 if all_pass else 1)

if __name__ == '__main__':
    main()
