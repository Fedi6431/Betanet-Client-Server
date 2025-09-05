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

# Constants
BETANET_VERSION = b"\x02"
SCION_TYPE_SINGLE_PATH = 0x01
SCION_TYPE_PATH_LIST = 0x03
HTX_ALPN = b"htx/1.1.0"
TICKET_KEY_ID = os.urandom(8)
TICKET_PUB = x25519.X25519PrivateKey.generate().public_key()

@dataclass
class SCIONHeader:
    ver: int
    type: int
    total_length: int
    payload_length: int
    path_segments: bytes

@dataclass
class HTXFrame:
    length: int
    type: int
    stream_id: int
    ciphertext: bytes

class BetanetClient:
    def __init__(self):
        self.private_key = x25519.X25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()
        self.ed25519_private_key = ed25519.Ed25519PrivateKey.generate()
        self.ed25519_public_key = self.ed25519_private_key.public_key()
        self.session_keys = {}
        self.nonce_salts = {}
        self.counter = 0

    def sha256(self, data: bytes) -> bytes:
        return hashlib.sha256(data).digest()

    def hkdf(self, ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
        return HKDF(
            algorithm=hashes.SHA256(),
            length=length,
            salt=salt,
            info=info,
            backend=default_backend()
        ).derive(ikm)

    def generate_access_ticket(self, ticket_pub: bytes, ticket_key_id: bytes, hour: int) -> Tuple[bytes, bytes]:
        cli_priv = x25519.X25519PrivateKey.generate()
        cli_pub = cli_priv.public_key()
        nonce32 = os.urandom(32)
        shared_secret = cli_priv.exchange(x25519.X25519PublicKey.from_public_bytes(ticket_pub))
        salt = self.sha256(b"betanet-ticket-v1" + ticket_key_id + struct.pack(">Q", hour))
        access_ticket = self.hkdf(shared_secret, salt, b"", 32)
        return cli_pub.public_bytes(Encoding.Raw, PublicFormat.Raw), access_ticket

    def create_scion_header(self, path_segments: bytes, payload: bytes) -> bytes:
        total_length = 4 + len(path_segments) + len(payload)
        header = struct.pack(
            ">BBHH",
            BETANET_VERSION[0],
            SCION_TYPE_SINGLE_PATH,
            total_length,
            len(payload)
        ) + path_segments
        return header + payload

    def create_htx_frame(self, frame_type: int, stream_id: int, plaintext: bytes, key: bytes, nonce_salt: bytes) -> bytes:
        aead = ChaCha20Poly1305(key)
        nonce = nonce_salt[:12] + struct.pack("<Q", self.counter)[:8]
        ciphertext = aead.encrypt(nonce, plaintext, None)
        frame = struct.pack(
            ">I B",
            len(ciphertext) - 16,  # Exclude tag length
            frame_type
        )
        if frame_type == 0:  # STREAM
            frame += struct.pack(">Q", stream_id)
        frame += ciphertext
        self.counter += 1
        return frame

    def connect(self, host: str, port: int):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((host, port))
            # Perform TLS handshake, calibration, and HTX setup here
            # For simplicity, we skip the full TLS/HTX handshake in this example
            print(f"Connected to {host}:{port}")
            # Example: Send a dummy HTX frame
            dummy_frame = self.create_htx_frame(0, 1, b"Hello, Betanet!", os.urandom(32), os.urandom(12))
            s.sendall(dummy_frame)

if __name__ == "__main__":
    client = BetanetClient()
    client.connect("example.betanet.node", 443)
