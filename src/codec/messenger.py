import json
import os
import base64
from typing import Any

from codec.cipher import Cipher, AsymmetricCipher
from codec.keys import KeyStore
from codec.message import Message
from codec.signer import Signer
from codec.errors import CryptoError, VerificationError


class SecureMessenger:
    """Main high-level API for secure messaging."""

    def __init__(self, keystore: KeyStore, cipher: Cipher, signer: Signer):
        self.keystore = keystore
        self.cipher = cipher
        self.signer = signer
        self.asymmetric_cipher = AsymmetricCipher()

    def send(
        self,
        plaintext: bytes,
        recipient_public_key: bytes,
        sender_private_key: bytes,
        sender_id: str,
        recipient_id: str,
    ) -> Message:
        """
        Sends an encrypted and signed message.

        Uses Hybrid Encryption:
        1. Generates a symmetric session key.
        2. Encrypts plaintext with session key (ChaCha20Poly1305).
        3. Encrypts session key with recipient's public key (RSA).
        4. Signs the final package with sender's private key (Ed25519/RSA).
        """

        # 1. Encrypt
        encrypted_payload_dict = self._encrypt_payload(plaintext, recipient_public_key)

        encrypted_bytes = json.dumps(encrypted_payload_dict).encode("utf-8")

        # 2. Sign
        signature = self.signer.sign(encrypted_bytes, sender_private_key)

        final_payload_struct = {
            "content": base64.b64encode(encrypted_bytes).decode("ascii"),
            "signature": base64.b64encode(signature).decode("ascii"),
        }
        final_payload = json.dumps(final_payload_struct).encode("utf-8")

        return Message(
            payload=final_payload,
            sender_id=sender_id,
            recipient_id=recipient_id,
            encrypted=True,
            signed=True,
        )

    def receive(
        self,
        message: Message,
        recipient_private_key: bytes,
        sender_public_key: bytes,
    ) -> bytes:
        """
        Receives and verifies a message.
        """
        if not message.encrypted or not message.signed:
            # We enforce security in this SecureMessenger implementation
            raise ValueError("Message must be encrypted and signed")

        try:
            wrapper = json.loads(message.payload.decode("utf-8"))
            encrypted_bytes = base64.b64decode(wrapper["content"])
            signature = base64.b64decode(wrapper["signature"])
        except (json.JSONDecodeError, KeyError) as e:
            raise ValueError("Invalid message payload format") from e

        # 1. Verify Signature
        if not self.signer.verify(encrypted_bytes, signature, sender_public_key):
            raise VerificationError("Invalid message signature")

        # 2. Decrypt
        try:
            encrypted_payload_dict = json.loads(encrypted_bytes.decode("utf-8"))
        except json.JSONDecodeError as e:
            raise CryptoError("Invalid encrypted content format") from e

        return self._decrypt_payload(encrypted_payload_dict, recipient_private_key)

    def _encrypt_payload(self, plaintext: bytes, recipient_public_key: bytes) -> dict:
        """Helper for hybrid encryption."""
        # Generate generic session key
        session_key = os.urandom(32)

        # Encrypt Key
        enc_session_key = self.asymmetric_cipher.encrypt(
            session_key, recipient_public_key
        )

        # Encrypt Data
        ciphertext = self.cipher.encrypt(plaintext, session_key)

        return {
            "k": base64.b64encode(enc_session_key).decode("ascii"),
            "c": base64.b64encode(ciphertext).decode("ascii"),
        }

    def _decrypt_payload(
        self, encrypted_payload: dict, recipient_private_key: bytes
    ) -> bytes:
        """Helper for hybrid decryption."""
        try:
            enc_session_key = base64.b64decode(encrypted_payload["k"])
            ciphertext = base64.b64decode(encrypted_payload["c"])
        except KeyError as e:
            raise CryptoError("Missing encryption fields") from e

        # Decrypt Session Key
        try:
            session_key = self.asymmetric_cipher.decrypt(
                enc_session_key, recipient_private_key
            )
        except Exception as e:
            raise CryptoError("Failed to decrypt session key") from e

        # Decrypt Data
        try:
            plaintext = self.cipher.decrypt(ciphertext, session_key)
        except Exception as e:
            raise CryptoError("Failed to decrypt message content") from e

        return plaintext
