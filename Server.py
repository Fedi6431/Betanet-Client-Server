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

# Constants
BETANET_VERSION = b"\x02"
SCION_TYPE_SINGLE_PATH = 0x01
TICKET_KEY_ID = os.urandom(8)
TICKET_PRIV = x25519.X25519PrivateKey.generate()
TICKET_PUB = TICKET_PRIV.public_key()

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

class BetanetServer:
    def __init__(self, host: str = "127.0.0.1", port: int = 443):
        self.host = host
        self.port = port
        self.ed25519_private_key = ed25519.Ed25519PrivateKey.generate()
        self.ed25519_public_key = self.ed25519_private_key.public_key()
        self.session_keys = {}
        self.nonce_salts = {}
        self.counter = 0
        self.ticket_key_id = TICKET_KEY_ID
        self.ticket_pub = TICKET_PUB.public_bytes(Encoding.Raw, PublicFormat.Raw)

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

    def verify_access_ticket(self, cli_pub: bytes, nonce32: bytes, access_ticket: bytes, hour: int) -> bool:
        shared_secret = TICKET_PRIV.exchange(x25519.X25519PublicKey.from_public_bytes(cli_pub))
        salt = self.sha256(b"betanet-ticket-v1" + self.ticket_key_id + struct.pack(">Q", hour))
        expected_ticket = self.hkdf(shared_secret, salt, b"", 32)
        return hmac.compare_digest(access_ticket, expected_ticket)

    def parse_scion_header(self, data: bytes) -> Optional[SCIONHeader]:
        if len(data) < 4:
            return None
        ver, type_, total_length = struct.unpack(">BBH", data[:4])
        if ver != BETANET_VERSION[0]:
            return None
        payload_length = struct.unpack(">H", data[4:6])[0]
        path_segments = data[6:6 + (total_length - 6 - payload_length)]
        return SCIONHeader(ver, type_, total_length, payload_length, path_segments)

    def parse_htx_frame(self, data: bytes, key: bytes, nonce_salt: bytes) -> Optional[HTXFrame]:
        if len(data) < 5:
            return None
        length, type_ = struct.unpack(">IB", data[:5])
        offset = 5
        stream_id = 0
        if type_ == 0:  # STREAM
            stream_id = struct.unpack(">Q", data[5:13])[0]
            offset = 13
        ciphertext = data[offset:offset + length + 16]
        aead = ChaCha20Poly1305(key)
        nonce = nonce_salt[:12] + struct.pack("<Q", self.counter)[:8]
        try:
            plaintext = aead.decrypt(nonce, ciphertext, None)
            self.counter += 1
            return HTXFrame(length, type_, stream_id, plaintext)
        except:
            return None

    def handle_client(self, conn: socket.socket, addr: Tuple[str, int]):
        print(f"Connection from {addr}")
        # Simulate receiving and verifying an access ticket
        # In a real implementation, this would be part of the TLS/HTX handshake
        try:
            data = conn.recv(1024)
            # Example: Parse SCION header
            scion_header = self.parse_scion_header(data)
            if scion_header:
                print(f"Received SCION packet: type={scion_header.type}, length={scion_header.total_length}")
            # Example: Parse HTX frame
            htx_frame = self.parse_htx_frame(data[6:], os.urandom(32), os.urandom(12))
            if htx_frame:
                print(f"Received HTX frame: type={htx_frame.type}, stream_id={htx_frame.stream_id}, data={htx_frame.ciphertext[:20]}...")
            # Simulate sending a response
            response = self.create_htx_frame(0, 2, b"Hello from Betanet Server!", os.urandom(32), os.urandom(12))
            conn.sendall(response)
        except Exception as e:
            print(f"Error: {e}")
        finally:
            conn.close()

    def create_htx_frame(self, frame_type: int, stream_id: int, plaintext: bytes, key: bytes, nonce_salt: bytes) -> bytes:
        aead = ChaCha20Poly1305(key)
        nonce = nonce_salt[:12] + struct.pack("<Q", self.counter)[:8]
        ciphertext = aead.encrypt(nonce, plaintext, None)
        frame = struct.pack(">IB", len(ciphertext) - 16, frame_type)
        if frame_type == 0:  # STREAM
            frame += struct.pack(">Q", stream_id)
        frame += ciphertext
        self.counter += 1
        return frame

    def start(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((self.host, self.port))
            s.listen()
            print(f"Betanet Server listening on {self.host}:{self.port}")
            while True:
                conn, addr = s.accept()
                self.handle_client(conn, addr)

if __name__ == "__main__":
    server = BetanetServer()
    server.start()
