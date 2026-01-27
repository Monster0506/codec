from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from codec.cipher import Cipher
from codec.keys import KeyPair
from codec.errors import CryptoError


class EncryptedSession:
    """
    Maintains a secure session between two parties using X25519 key exchange.

    Note: This implements an Ephemeral-Ephemeral Diffie-Hellman handshake.
    The identity keys (passed in __init__) should ideally be used to SIGN the handshake
    to prevent MITM, but for this basic implementation we will focus on the key exchange logic.
    """

    def __init__(self, keypair: KeyPair, peer_public_key: bytes):
        """
        Args:
            keypair: My Long-term Identity identity key (Not actually used in basic DH,
                     but reserved for potential signing of handshake).
            peer_public_key: Peer's Long-term Identity key.
        """
        self.identity_keypair = keypair
        self.peer_identity_key = peer_public_key

        # Ephemeral key for this session
        self._ephemeral_private = x25519.X25519PrivateKey.generate()
        self._ephemeral_public = self._ephemeral_private.public_key()

        self.session_key: bytes | None = None
        self.cipher = Cipher()

    def establish(self) -> bytes:
        """
        Initiates the session.
        Returns my ephemeral public key bytes to send to peer.
        """
        return self._ephemeral_public.public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
        )

    def process_handshake(self, peer_data: bytes) -> None:
        """
        Processes peer's ephemeral public key and derives session key.
        """
        try:
            peer_ephemeral = x25519.X25519PublicKey.from_public_bytes(peer_data)
            shared_secret = self._ephemeral_private.exchange(peer_ephemeral)

            # Derive session key using HKDF
            self.session_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b"handshake data",
            ).derive(shared_secret)

        except Exception as e:
            raise CryptoError("Handshake failed") from e

    def encrypt_message(self, plaintext: bytes) -> bytes:
        if not self.session_key:
            raise CryptoError("Session not established")
        return self.cipher.encrypt(plaintext, self.session_key)

    def decrypt_message(self, ciphertext: bytes) -> bytes:
        if not self.session_key:
            raise CryptoError("Session not established")
        return self.cipher.decrypt(ciphertext, self.session_key)
