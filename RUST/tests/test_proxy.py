"""
Proxy functionality security and functionality tests
"""

import pytest
import socket
from unittest.mock import Mock, patch, MagicMock
import socks
from sft import SecureFileTransferNode


class TestProxyConfiguration:
    """Validate proxy parameter handling"""

    def test_proxy_none_creates_standard_socket(self):
        """Verify standard socket creation when no proxy configured"""
        node = SecureFileTransferNode('client', proxy_info=None)
        sock = node._create_socket()
        assert isinstance(sock, socket.socket)
        assert not isinstance(sock, socks.socksocket)

    def test_proxy_empty_dict_creates_standard_socket(self):
        """Verify standard socket when proxy_info is empty"""
        node = SecureFileTransferNode('client', proxy_info={})
        sock = node._create_socket()
        assert isinstance(sock, socket.socket)

    def test_proxy_missing_host_raises_valueerror(self):
        """Verify validation rejects missing proxy host"""
        proxy_info = {
            "type": "socks5",
            "port": 1080
        }
        node = SecureFileTransferNode('client', proxy_info=proxy_info)
        with pytest.raises(ValueError, match="requires both host and port"):
            node._create_socket()

    def test_proxy_missing_port_raises_valueerror(self):
        """Verify validation rejects missing proxy port"""
        proxy_info = {
            "type": "socks5",
            "host": "127.0.0.1"
        }
        node = SecureFileTransferNode('client', proxy_info=proxy_info)
        with pytest.raises(ValueError, match="requires both host and port"):
            node._create_socket()

    def test_proxy_invalid_port_type_raises_valueerror(self):
        """Verify validation rejects non-integer port"""
        proxy_info = {
            "type": "socks5",
            "host": "127.0.0.1",
            "port": "invalid"
        }
        node = SecureFileTransferNode('client', proxy_info=proxy_info)
        with pytest.raises(ValueError, match="must be between 1 and 65535"):
            node._create_socket()

    def test_proxy_port_too_low_raises_valueerror(self):
        """Verify validation rejects port below valid range"""
        proxy_info = {
            "type": "socks5",
            "host": "127.0.0.1",
            "port": 0
        }
        node = SecureFileTransferNode('client', proxy_info=proxy_info)
        with pytest.raises(ValueError, match="must be between 1 and 65535"):
            node._create_socket()

    def test_proxy_port_too_high_raises_valueerror(self):
        """Verify validation rejects port above valid range"""
        proxy_info = {
            "type": "socks5",
            "host": "127.0.0.1",
            "port": 65536
        }
        node = SecureFileTransferNode('client', proxy_info=proxy_info)
        with pytest.raises(ValueError, match="must be between 1 and 65535"):
            node._create_socket()

    def test_proxy_unsupported_type_raises_valueerror(self):
        """Verify validation rejects unsupported proxy types"""
        proxy_info = {
            "type": "ftp",
            "host": "127.0.0.1",
            "port": 1080
        }
        node = SecureFileTransferNode('client', proxy_info=proxy_info)
        with pytest.raises(ValueError, match="Unsupported proxy type"):
            node._create_socket()


class TestProxySocketCreation:
    """Validate proxy socket creation and configuration"""

    @patch('sft.socks.socksocket')
    def test_socks5_socket_creation(self, mock_socksocket):
        """Verify SOCKS5 proxy socket configuration"""
        mock_socket = MagicMock()
        mock_socksocket.return_value = mock_socket

        proxy_info = {
            "type": "socks5",
            "host": "127.0.0.1",
            "port": 1080
        }
        node = SecureFileTransferNode('client', proxy_info=proxy_info)
        sock = node._create_socket()

        mock_socket.set_proxy.assert_called_once_with(
            socks.SOCKS5,
            "127.0.0.1",
            1080,
            username=None,
            password=None
        )

    @patch('sft.socks.socksocket')
    def test_socks4_socket_creation(self, mock_socksocket):
        """Verify SOCKS4 proxy socket configuration"""
        mock_socket = MagicMock()
        mock_socksocket.return_value = mock_socket

        proxy_info = {
            "type": "socks4",
            "host": "192.168.1.1",
            "port": 1081
        }
        node = SecureFileTransferNode('client', proxy_info=proxy_info)
        sock = node._create_socket()

        mock_socket.set_proxy.assert_called_once_with(
            socks.SOCKS4,
            "192.168.1.1",
            1081,
            username=None,
            password=None
        )

    @patch('sft.socks.socksocket')
    def test_http_proxy_socket_creation(self, mock_socksocket):
        """Verify HTTP proxy socket configuration"""
        mock_socket = MagicMock()
        mock_socksocket.return_value = mock_socket

        proxy_info = {
            "type": "http",
            "host": "proxy.example.com",
            "port": 8080
        }
        node = SecureFileTransferNode('client', proxy_info=proxy_info)
        sock = node._create_socket()

        mock_socket.set_proxy.assert_called_once_with(
            socks.HTTP,
            "proxy.example.com",
            8080,
            username=None,
            password=None
        )

    @patch('sft.socks.socksocket')
    def test_authenticated_proxy_socket_creation(self, mock_socksocket):
        """Verify authenticated proxy configuration"""
        mock_socket = MagicMock()
        mock_socksocket.return_value = mock_socket

        proxy_info = {
            "type": "socks5",
            "host": "127.0.0.1",
            "port": 1080,
            "user": "testuser",
            "pass": "testpass"
        }
        node = SecureFileTransferNode('client', proxy_info=proxy_info)
        sock = node._create_socket()

        mock_socket.set_proxy.assert_called_once_with(
            socks.SOCKS5,
            "127.0.0.1",
            1080,
            username="testuser",
            password="testpass"
        )


class TestProxyErrorHandling:
    """Validate proxy error handling"""

    @patch('sft.socks.socksocket')
    def test_proxy_error_raises_connection_error(self, mock_socksocket):
        """Verify ProxyError is caught and converted"""
        mock_socket = MagicMock()
        mock_socket.set_proxy.side_effect = socks.ProxyError("Connection refused")
        mock_socksocket.return_value = mock_socket

        proxy_info = {
            "type": "socks5",
            "host": "127.0.0.1",
            "port": 1080
        }
        node = SecureFileTransferNode('client', proxy_info=proxy_info)

        with pytest.raises(ConnectionError, match="Proxy initialization failed"):
            node._create_socket()

    @patch('sft.socks.socksocket')
    def test_general_proxy_error_raises_connection_error(self, mock_socksocket):
        """Verify GeneralProxyError is caught and converted"""
        mock_socket = MagicMock()
        mock_socket.set_proxy.side_effect = socks.GeneralProxyError("Invalid configuration")
        mock_socksocket.return_value = mock_socket

        proxy_info = {
            "type": "socks5",
            "host": "127.0.0.1",
            "port": 1080
        }
        node = SecureFileTransferNode('client', proxy_info=proxy_info)

        with pytest.raises(ConnectionError, match="Proxy initialization failed"):
            node._create_socket()

    @patch('sft.socks.socksocket')
    def test_proxy_connection_error_raises_connection_error(self, mock_socksocket):
        """Verify ProxyConnectionError is caught and converted"""
        mock_socket = MagicMock()
        mock_socket.set_proxy.side_effect = socks.ProxyConnectionError("Timeout")
        mock_socksocket.return_value = mock_socket

        proxy_info = {
            "type": "socks5",
            "host": "127.0.0.1",
            "port": 1080
        }
        node = SecureFileTransferNode('client', proxy_info=proxy_info)

        with pytest.raises(ConnectionError, match="Proxy initialization failed"):
            node._create_socket()

    @patch('sft.socks.socksocket')
    def test_unexpected_error_propagates(self, mock_socksocket):
        """Verify unexpected exceptions are propagated"""
        mock_socket = MagicMock()
        mock_socket.set_proxy.side_effect = RuntimeError("Unexpected error")
        mock_socksocket.return_value = mock_socket

        proxy_info = {
            "type": "socks5",
            "host": "127.0.0.1",
            "port": 1080
        }
        node = SecureFileTransferNode('client', proxy_info=proxy_info)

        with pytest.raises(RuntimeError):
            node._create_socket()


class TestProxyTypeValidation:
    """Validate proxy type string handling"""

    @patch('sft.socks.socksocket')
    def test_uppercase_socks5_accepted(self, mock_socksocket):
        """Verify uppercase SOCKS5 is normalized"""
        mock_socket = MagicMock()
        mock_socksocket.return_value = mock_socket

        proxy_info = {
            "type": "SOCKS5",
            "host": "127.0.0.1",
            "port": 1080
        }
        node = SecureFileTransferNode('client', proxy_info=proxy_info)
        node._create_socket()

        mock_socket.set_proxy.assert_called_once()
        assert mock_socket.set_proxy.call_args[0][0] == socks.SOCKS5

    @patch('sft.socks.socksocket')
    def test_mixed_case_http_accepted(self, mock_socksocket):
        """Verify mixed case HTTP is normalized"""
        mock_socket = MagicMock()
        mock_socksocket.return_value = mock_socket

        proxy_info = {
            "type": "HtTp",
            "host": "127.0.0.1",
            "port": 8080
        }
        node = SecureFileTransferNode('client', proxy_info=proxy_info)
        node._create_socket()

        mock_socket.set_proxy.assert_called_once()
        assert mock_socket.set_proxy.call_args[0][0] == socks.HTTP


class TestProxyCredentialValidation:
    """Validate proxy credential input sanitization"""

    def test_null_byte_in_username_raises_valueerror(self):
        """Verify null byte in username is rejected"""
        proxy_info = {
            "type": "socks5",
            "host": "127.0.0.1",
            "port": 1080,
            "user": "test\x00user",
            "pass": "password"
        }
        node = SecureFileTransferNode('client', proxy_info=proxy_info)
        with pytest.raises(ValueError, match="Invalid proxy username"):
            node._create_socket()

    def test_null_byte_in_password_raises_valueerror(self):
        """Verify null byte in password is rejected"""
        proxy_info = {
            "type": "socks5",
            "host": "127.0.0.1",
            "port": 1080,
            "user": "testuser",
            "pass": "pass\x00word"
        }
        node = SecureFileTransferNode('client', proxy_info=proxy_info)
        with pytest.raises(ValueError, match="Invalid proxy password"):
            node._create_socket()

    def test_username_too_long_raises_valueerror(self):
        """Verify excessively long username is rejected"""
        proxy_info = {
            "type": "socks5",
            "host": "127.0.0.1",
            "port": 1080,
            "user": "a" * 256,
            "pass": "password"
        }
        node = SecureFileTransferNode('client', proxy_info=proxy_info)
        with pytest.raises(ValueError, match="Invalid proxy username"):
            node._create_socket()

    def test_password_too_long_raises_valueerror(self):
        """Verify excessively long password is rejected"""
        proxy_info = {
            "type": "socks5",
            "host": "127.0.0.1",
            "port": 1080,
            "user": "testuser",
            "pass": "p" * 256
        }
        node = SecureFileTransferNode('client', proxy_info=proxy_info)
        with pytest.raises(ValueError, match="Invalid proxy password"):
            node._create_socket()

    @patch('sft.socks.socksocket')
    def test_valid_credentials_accepted(self, mock_socksocket):
        """Verify valid credentials pass validation"""
        mock_socket = MagicMock()
        mock_socksocket.return_value = mock_socket

        proxy_info = {
            "type": "socks5",
            "host": "127.0.0.1",
            "port": 1080,
            "user": "validuser123",
            "pass": "validpass456"
        }
        node = SecureFileTransferNode('client', proxy_info=proxy_info)
        sock = node._create_socket()

        mock_socket.set_proxy.assert_called_once()

    @patch('sft.socks.socksocket')
    def test_max_length_credentials_accepted(self, mock_socksocket):
        """Verify maximum length credentials are accepted"""
        mock_socket = MagicMock()
        mock_socksocket.return_value = mock_socket

        proxy_info = {
            "type": "socks5",
            "host": "127.0.0.1",
            "port": 1080,
            "user": "u" * 255,
            "pass": "p" * 255
        }
        node = SecureFileTransferNode('client', proxy_info=proxy_info)
        sock = node._create_socket()

        mock_socket.set_proxy.assert_called_once()
