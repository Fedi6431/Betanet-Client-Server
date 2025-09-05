import os
import socket
import struct
import hashlib
import hmac
from typing import Optional, Tuple
from dataclasses import dataclass
from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives import hashes, hmac as crypto_hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

# --- Constants ---
# Betanet protocol version (as per specification)
BETANET_VERSION = b"\x02"
# SCION packet type for single path (as per specification)
SCION_TYPE_SINGLE_PATH = 0x01
# Randomly generated ticket key ID and private/public key pair for access ticket system
TICKET_KEY_ID = os.urandom(8)
TICKET_PRIV = x25519.X25519PrivateKey.generate()
TICKET_PUB = TICKET_PRIV.public_key()

# --- Data Structures ---
@dataclass
class SCIONHeader:
    """Represents a SCION packet header."""
    ver: int           # Protocol version
    type: int          # Packet type (e.g., single path)
    total_length: int  # Total length of the header + payload
    payload_length: int # Length of the payload
    path_segments: bytes # Path segments for SCION routing

@dataclass
class HTXFrame:
    """Represents an HTX frame."""
    length: int       # Length of the ciphertext (excluding tag)
    type: int         # Frame type (e.g., STREAM, PING, CLOSE)
    stream_id: int    # Stream identifier (for STREAM frames)
    ciphertext: bytes # Encrypted payload or plaintext after decryption

# --- Betanet Server Class ---
class BetanetServer:
    def __init__(self, host: str = "127.0.0.1", port: int = 443):
        """Initialize the Betanet server with cryptographic keys and session state.
        Args:
            host: Server hostname or IP address.
            port: Server port.
        """
        self.host = host
        self.port = port
        # Generate Ed25519 key pair for signing
        self.ed25519_private_key = ed25519.Ed25519PrivateKey.generate()
        self.ed25519_public_key = self.ed25519_private_key.public_key()
        # Dictionaries to store session keys and nonce salts
        self.session_keys = {}
        self.nonce_salts = {}
        # Counter for nonce generation
        self.counter = 0
        # Ticket key ID and public key for access ticket verification
        self.ticket_key_id = TICKET_KEY_ID
        self.ticket_pub = TICKET_PUB.public_bytes(Encoding.Raw, PublicFormat.Raw)

    def sha256(self, data: bytes) -> bytes:
        """Compute SHA-256 hash of the input data.
        Args:
            data: Input data to hash.
        Returns:
            SHA-256 hash digest.
        """
        return hashlib.sha256(data).digest()

    def hkdf(self, ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
        """Derive a key using HKDF-SHA256.
        Args:
            ikm: Input key material.
            salt: Optional salt value.
            info: Application-specific context.
            length: Length of the output key.
        Returns:
            Derived key material.
        """
        return HKDF(
            algorithm=hashes.SHA256(),
            length=length,
            salt=salt,
            info=info,
            backend=default_backend()
        ).derive(ikm)

    def verify_access_ticket(self, cli_pub: bytes, nonce32: bytes, access_ticket: bytes, hour: int) -> bool:
        """Verify the access ticket sent by the client.
        Args:
            cli_pub: Client's public key.
            nonce32: Nonce used in ticket generation.
            access_ticket: Access ticket to verify.
            hour: Current hour (floor of Unix time / 3600).
        Returns:
            True if the access ticket is valid, False otherwise.
        """
        # Perform key exchange to get shared secret
        shared_secret = TICKET_PRIV.exchange(x25519.X25519PublicKey.from_public_bytes(cli_pub))
        # Compute salt for HKDF
        salt = self.sha256(b"betanet-ticket-v1" + self.ticket_key_id + struct.pack(">Q", hour))
        # Derive the expected access ticket using HKDF
        expected_ticket = self.hkdf(shared_secret, salt, b"", 32)
        # Compare the expected ticket with the received ticket
        return hmac.compare_digest(access_ticket, expected_ticket)

    def parse_scion_header(self, data: bytes) -> Optional[SCIONHeader]:
        """Parse a SCION packet header from the received data.
        Args:
            data: Raw bytes received from the client.
        Returns:
            SCIONHeader object if parsing is successful, None otherwise.
        """
        if len(data) < 4:
            return None
        # Unpack version, type, and total length
        ver, type_, total_length = struct.unpack(">BBH", data[:4])
        if ver != BETANET_VERSION[0]:
            return None
        # Unpack payload length
        payload_length = struct.unpack(">H", data[4:6])[0]
        # Extract path segments
        path_segments = data[6:6 + (total_length - 6 - payload_length)]
        return SCIONHeader(ver, type_, total_length, payload_length, path_segments)

    def parse_htx_frame(self, data: bytes, key: bytes, nonce_salt: bytes) -> Optional[HTXFrame]:
        """Parse an HTX frame from the received data.
        Args:
            data: Raw bytes received from the client.
            key: Decryption key.
            nonce_salt: Salt for nonce generation.
        Returns:
            HTXFrame object if parsing and decryption are successful, None otherwise.
        """
        if len(data) < 5:
            return None
        # Unpack length and type
        length, type_ = struct.unpack(">IB", data[:5])
        offset = 5
        stream_id = 0
        # Extract stream_id if this is a STREAM frame
        if type_ == 0:  # STREAM
            stream_id = struct.unpack(">Q", data[5:13])[0]
            offset = 13
        # Extract ciphertext
        ciphertext = data[offset:offset + length + 16]
        aead = ChaCha20Poly1305(key)
        # Construct a 12-byte nonce: 4 bytes from nonce_salt, 8 bytes from counter
        nonce = nonce_salt[:4] + struct.pack("<Q", self.counter)
        try:
            # Decrypt the ciphertext
            plaintext = aead.decrypt(nonce, ciphertext, None)
            self.counter += 1
            return HTXFrame(length, type_, stream_id, plaintext)
        except Exception as e:
            print(f"Decryption failed: {e}")
            return None

    def create_htx_frame(self, frame_type: int, stream_id: int, plaintext: bytes, key: bytes, nonce_salt: bytes) -> bytes:
        """Create an HTX frame (encrypted and formatted).
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
        # Pack frame header: length (4 bytes), type (1 byte)
        frame = struct.pack(">IB", len(ciphertext) - 16, frame_type)
        # Add stream_id if this is a STREAM frame
        if frame_type == 0:  # STREAM
            frame += struct.pack(">Q", stream_id)
        # Append ciphertext
        frame += ciphertext
        self.counter += 1
        return frame

    def handle_client(self, conn: socket.socket, addr: Tuple[str, int]):
        """Handle communication with a connected client.
        Args:
            conn: Socket connection to the client.
            addr: Client address (host, port).
        """
        print(f"Connection from {addr}")
        try:
            # Receive the shared key and nonce salt from the client
            key_and_salt = conn.recv(44)  # 32 bytes for key + 12 bytes for nonce salt
            if len(key_and_salt) != 44:
                raise ValueError("Invalid key/salt length")
            shared_key = key_and_salt[:32]
            nonce_salt = key_and_salt[32:]
            self.counter = 0  # Reset counter for this session
            while True:
                # Receive the HTX frame
                data = conn.recv(1024)
                if not data:
                    break  # Client closed the connection
                # Parse the HTX frame
                htx_frame = self.parse_htx_frame(data, shared_key, nonce_salt)
                if htx_frame:
                    print(f"Received HTX frame: type={htx_frame.type}, stream_id={htx_frame.stream_id}, data={htx_frame.ciphertext.decode('utf-8', errors='ignore')}")
                    # Echo back or send a response
                    if htx_frame.type == 0:  # STREAM
                        response = self.create_htx_frame(0, htx_frame.stream_id, b"Server received: " + htx_frame.ciphertext, shared_key, nonce_salt)
                        conn.sendall(response)
                    elif htx_frame.type == 2:  # CLOSE
                        print("Client requested to close the connection.")
                        break
        except Exception as e:
            print(f"Error: {e}")
        finally:
            conn.close()
            print(f"Connection with {addr} closed.")

    def start(self):
        """Start the Betanet server and listen for incoming connections."""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((self.host, self.port))
            s.listen()
            print(f"Betanet Server listening on {self.host}:{self.port}")
            while True:
                # Accept incoming connections
                conn, addr = s.accept()
                self.handle_client(conn, addr)

# --- Main Execution ---
if __name__ == "__main__":
    # Create and start the server
    server = BetanetServer()
    server.start()
