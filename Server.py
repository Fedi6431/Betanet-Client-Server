import os
import socket
import hashlib
import hmac
import struct
import time
from typing import Optional, Tuple, List
from dataclasses import dataclass
from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives import hashes, hmac as crypto_hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

# --- Constants ---
# Betanet protocol version (as per spec)
BETANET_VERSION = b"\x02"
# SCION packet types (as per spec)
SCION_TYPE_SINGLE_PATH = 0x01
SCION_TYPE_PATH_LIST = 0x03
# HTX ALPN identifier (as per spec)
HTX_ALPN = b"htx/1.1.0"
# Randomly generated ticket key ID and public key for access ticket system
TICKET_KEY_ID = os.urandom(8)
TICKET_PUB = x25519.X25519PrivateKey.generate().public_key()

# --- Data Structures ---
@dataclass
class SCIONHeader:
    """Represents a SCION packet header."""
    ver: int       # Protocol version
    type: int      # Packet type (single path or path list)
    total_length: int  # Total length of the header + payload
    payload_length: int  # Length of the payload
    path_segments: bytes  # Path segments for SCION routing

@dataclass
class HTXFrame:
    """Represents an HTX frame."""
    length: int       # Length of the ciphertext (excluding tag)
    type: int         # Frame type (e.g., STREAM, PING, CLOSE)
    stream_id: int    # Stream identifier (for STREAM frames)
    ciphertext: bytes # Encrypted payload

# --- Betanet Client Class ---
class BetanetClient:
    def __init__(self):
        """Initialize the Betanet client with cryptographic keys and session state."""
        # Generate X25519 key pair for session encryption
        self.private_key = x25519.X25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()
        # Generate Ed25519 key pair for signing
        self.ed25519_private_key = ed25519.Ed25519PrivateKey.generate()
        self.ed25519_public_key = self.ed25519_private_key.public_key()
        # Dictionaries to store session keys and nonce salts
        self.session_keys = {}
        self.nonce_salts = {}
        # Counter for nonce generation
        self.counter = 0

    def sha256(self, data: bytes) -> bytes:
        """Compute SHA-256 hash of the input data."""
        return hashlib.sha256(data).digest()

    def hkdf(self, ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
        """Derive a key using HKDF-SHA256."""
        return HKDF(
            algorithm=hashes.SHA256(),
            length=length,
            salt=salt,
            info=info,
            backend=default_backend()
        ).derive(ikm)

    def generate_access_ticket(self, ticket_pub: bytes, ticket_key_id: bytes, hour: int) -> Tuple[bytes, bytes]:
        """
        Generate an access ticket for Betanet authentication.

        Args:
            ticket_pub: Server's public key for ticket generation.
            ticket_key_id: Unique identifier for the ticket key.
            hour: Current hour (floor of Unix time / 3600).

        Returns:
            Tuple of (client public key, access ticket).
        """
        # Generate ephemeral X25519 key pair for this ticket
        cli_priv = x25519.X25519PrivateKey.generate()
        cli_pub = cli_priv.public_key()
        nonce32 = os.urandom(32)
        # Perform key exchange to get shared secret
        shared_secret = cli_priv.exchange(x25519.X25519PublicKey.from_public_bytes(ticket_pub))
        # Compute salt for HKDF
        salt = self.sha256(b"betanet-ticket-v1" + ticket_key_id + struct.pack(">Q", hour))
        # Derive access ticket using HKDF
        access_ticket = self.hkdf(shared_secret, salt, b"", 32)
        return cli_pub.public_bytes(Encoding.Raw, PublicFormat.Raw), access_ticket

    def create_scion_header(self, path_segments: bytes, payload: bytes) -> bytes:
        """
        Create a SCION packet header.

        Args:
            path_segments: SCION path segments.
            payload: Payload to be sent.

        Returns:
            Bytes representing the SCION header + payload.
        """
        total_length = 4 + len(path_segments) + len(payload)
        header = struct.pack(
            ">BBHH",  # Big-endian: version, type, total_length, payload_length
            BETANET_VERSION[0],
            SCION_TYPE_SINGLE_PATH,
            total_length,
            len(payload)
        ) + path_segments
        return header + payload

    def create_htx_frame(self, frame_type: int, stream_id: int, plaintext: bytes, key: bytes, nonce_salt: bytes) -> bytes:
        """
        Create an HTX frame (encrypted and formatted).

        Args:
            frame_type: Type of the frame (e.g., 0 for STREAM).
            stream_id: Stream identifier.
            plaintext: Data to encrypt.
            key: Encryption key.
            nonce_salt: Salt for nonce generation.

        Returns:
            Bytes representing the HTX frame.
        """
        aead = ChaCha20Poly1305(key)
        # Construct a 12-byte nonce: 4 bytes from nonce_salt, 8 bytes from counter
        nonce = nonce_salt[:4] + struct.pack("<Q", self.counter)
        # Encrypt the plaintext
        ciphertext = aead.encrypt(nonce, plaintext, None)
        # Pack frame header: length (3 bytes), type (1 byte)
        frame = struct.pack(">IB", len(ciphertext) - 16, frame_type)
        # Add stream_id if this is a STREAM frame
        if frame_type == 0:  # STREAM
            frame += struct.pack(">Q", stream_id)
        # Append ciphertext
        frame += ciphertext
        self.counter += 1
        return frame

    def connect(self, host: str, port: int):
        """
        Connect to a Betanet server and send a test frame.

        Args:
            host: Server hostname or IP.
            port: Server port.
        """
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((host, port))
            # In a real implementation, perform TLS handshake and HTX calibration here
            print(f"Connected to {host}:{port}")
            # Example: Send a dummy HTX frame
            # Note: In a real scenario, use proper session keys and nonce salts
            dummy_frame = self.create_htx_frame(0, 1, b"Hello, Betanet!", os.urandom(32), os.urandom(12))
            s.sendall(dummy_frame)

# --- Main Execution ---
if __name__ == "__main__":
    # Create and run the client
    client = BetanetClient()
    client.connect("127.0.0.1", 443)
