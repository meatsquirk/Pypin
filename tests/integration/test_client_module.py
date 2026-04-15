"""
Tests for DCPP Client Module

Tests for DCPPClient class methods and CLI functionality.
"""

import socket
import struct
import time
from unittest.mock import Mock, patch, MagicMock

import pytest

from dcpp_python.client import DCPPClient, main
from dcpp_python.core.constants import MAGIC_BYTES, MessageType, Capability
from dcpp_python.framing import Profile1Framer
from dcpp_python.messages import Hello


# =============================================================================
# DCPPClient Tests
# =============================================================================

class TestDCPPClient:
    """Tests for DCPPClient class."""

    def test_create_client_defaults(self):
        """Create client with defaults."""
        client = DCPPClient()

        assert client.host == "127.0.0.1"
        assert client.port == 4001
        assert client.timeout == 10.0
        assert client.socket is None

    def test_create_client_custom(self):
        """Create client with custom settings."""
        client = DCPPClient(
            host="192.168.1.1",
            port=9999,
            timeout=30.0
        )

        assert client.host == "192.168.1.1"
        assert client.port == 9999
        assert client.timeout == 30.0

    def test_client_has_keypair(self):
        """Client should have signing and verify keys."""
        client = DCPPClient()

        assert client.signing_key is not None
        assert client.verify_key is not None

    def test_close_without_socket(self):
        """Close should handle no socket gracefully."""
        client = DCPPClient()
        client.close()  # Should not raise
        assert client.socket is None


class TestDCPPClientWithMockSocket:
    """Tests for DCPPClient with mocked socket."""

    @pytest.fixture
    def client(self):
        return DCPPClient()

    @pytest.fixture
    def mock_socket(self):
        return Mock(spec=socket.socket)

    def test_connect(self, client, mock_socket):
        """Connect establishes socket connection."""
        with patch('socket.socket', return_value=mock_socket):
            client.connect()

            mock_socket.settimeout.assert_called_once_with(client.timeout)
            mock_socket.connect.assert_called_once_with((client.host, client.port))

    def test_close_with_socket(self, client, mock_socket):
        """Close closes and clears socket."""
        client.socket = mock_socket

        client.close()

        mock_socket.close.assert_called_once()
        assert client.socket is None

    def test_send_message_profile1(self, client, mock_socket):
        """Send message with Profile 1 framing."""
        client.socket = mock_socket

        client.send_message(MessageType.HELLO, {"test": "data"})

        mock_socket.sendall.assert_called_once()
        sent_data = mock_socket.sendall.call_args[0][0]

        # Should start with magic bytes
        assert sent_data[:4] == MAGIC_BYTES

    def test_send_message_not_connected(self, client):
        """Send message raises when not connected."""
        with pytest.raises(RuntimeError, match="Not connected"):
            client.send_message(MessageType.HELLO, {})

    def test_recv_exactly(self, client, mock_socket):
        """_recv_exactly receives exact number of bytes."""
        client.socket = mock_socket
        mock_socket.recv.side_effect = [b"abcd", b"efgh"]

        result = client._recv_exactly(8)

        assert result == b"abcdefgh"
        assert mock_socket.recv.call_count == 2

    def test_recv_exactly_connection_closed(self, client, mock_socket):
        """_recv_exactly raises on connection close."""
        client.socket = mock_socket
        mock_socket.recv.return_value = b""  # Connection closed

        with pytest.raises(ConnectionError, match="Connection closed"):
            client._recv_exactly(8)


class TestDCPPClientMessageMethods:
    """Tests for DCPPClient message sending methods."""

    @pytest.fixture
    def client(self):
        return DCPPClient()

    def test_send_hello_payload(self, client):
        """send_hello creates correct Hello message."""
        mock_socket = Mock(spec=socket.socket)
        client.socket = mock_socket

        # Mock receive to return a valid response
        hello_response = Hello(
            version="1.0.0",
            node_id=b"\x00" * 32,
            timestamp=int(time.time()),
            collections=[],
            capabilities=[Capability.GUARDIAN],
        )
        response_frame = Profile1Framer.encode(
            MessageType.HELLO,
            hello_response.to_dict()
        )

        # Simulate receiving the response (20-byte header for Profile 1)
        mock_socket.recv.side_effect = [
            response_frame[:20],  # Header (20 bytes)
            response_frame[20:],  # Payload
        ]

        with patch.object(client, '_recv_exactly', side_effect=[
            response_frame[:20],  # Header (20 bytes)
            response_frame[20:],  # Payload
        ]):
            result = client.send_hello(collections=["test:col"])

        # Verify send was called
        mock_socket.sendall.assert_called_once()

    def test_send_get_peers_payload(self, client):
        """send_get_peers creates correct GetPeers message."""
        mock_socket = Mock(spec=socket.socket)
        client.socket = mock_socket

        # Check the sendall call has correct message type
        client.send_message = Mock()

        # Call through send_message which we've mocked
        with patch.object(client, 'receive_message', return_value=None):
            client.send_get_peers("test:collection", max_peers=10)

        client.send_message.assert_called_once()
        call_args = client.send_message.call_args
        assert call_args[0][0] == MessageType.GET_PEERS

    def test_send_get_manifest_payload(self, client):
        """send_get_manifest creates correct GetManifest message."""
        mock_socket = Mock(spec=socket.socket)
        client.socket = mock_socket

        client.send_message = Mock()

        with patch.object(client, 'receive_message', return_value=None):
            client.send_get_manifest("test:collection")

        client.send_message.assert_called_once()
        call_args = client.send_message.call_args
        assert call_args[0][0] == MessageType.GET_MANIFEST

    def test_send_goodbye(self, client):
        """send_goodbye sends GOODBYE message."""
        mock_socket = Mock(spec=socket.socket)
        client.socket = mock_socket

        client.send_goodbye()

        mock_socket.sendall.assert_called_once()


# =============================================================================
# Receive Message Tests
# =============================================================================

class TestReceiveMessage:
    """Tests for receive_message method."""

    @pytest.fixture
    def client(self):
        return DCPPClient()

    def test_receive_message_profile1(self, client):
        """Receive Profile 1 message."""
        # Create a valid Profile 1 response
        hello = Hello(
            version="1.0.0",
            node_id=b"\x00" * 32,
            timestamp=int(time.time()),
            collections=[],
            capabilities=[],
        )
        encoded = Profile1Framer.encode(MessageType.HELLO, hello.to_dict())

        mock_socket = Mock(spec=socket.socket)
        client.socket = mock_socket

        # Setup mock to return header and payload (20-byte header for Profile 1)
        with patch.object(client, '_recv_exactly', side_effect=[
            encoded[:20],  # Header (20 bytes for Profile 1)
            encoded[20:],  # Rest of message
        ]):
            result = client.receive_message()

        assert result is not None
        msg_type, message = result
        assert msg_type == MessageType.HELLO

    def test_receive_message_not_connected(self, client):
        """Receive message raises when not connected."""
        with pytest.raises(RuntimeError, match="Not connected"):
            client.receive_message()

    def test_receive_message_invalid_magic(self, client):
        """Receive message raises on invalid magic."""
        mock_socket = Mock(spec=socket.socket)
        client.socket = mock_socket

        # Return invalid magic bytes
        with patch.object(client, '_recv_exactly', return_value=b"XXXX" + b"\x00" * 12):
            with pytest.raises(ValueError, match="Invalid magic bytes"):
                client.receive_message()


# =============================================================================
# CLI Main Function Tests
# =============================================================================

class TestCLIMain:
    """Tests for CLI main function."""

    def test_main_hello_command(self):
        """Main handles hello command."""
        with patch('sys.argv', ['dcpp-client', 'hello']):
            with patch.object(DCPPClient, 'connect'):
                with patch.object(DCPPClient, 'send_hello', return_value=None):
                    with patch.object(DCPPClient, 'close'):
                        result = main()

        assert result == 0

    def test_main_get_peers_no_args(self):
        """Main returns 1 for get-peers without collection_id."""
        with patch('sys.argv', ['dcpp-client', 'get-peers']):
            with patch.object(DCPPClient, 'connect'):
                with patch.object(DCPPClient, 'close'):
                    result = main()

        assert result == 1

    def test_main_connection_error(self):
        """Main handles connection errors."""
        with patch('sys.argv', ['dcpp-client', 'hello']):
            with patch.object(DCPPClient, 'connect', side_effect=ConnectionError("test")):
                with patch.object(DCPPClient, 'close'):
                    result = main()

        assert result == 1
