import os

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305


class Cipher:
    """Handles symmetric encryption using ChaCha20Poly1305."""

    def encrypt(
        self, plaintext: bytes, key: bytes, associated_data: bytes | None = None
    ) -> bytes:
        """
        Encrypts plaintext using ChaCha20Poly1305.

        Args:
            plaintext: Data to encrypt
            key: 32-byte secret key
            associated_data: Optional AAD

        Returns:
            bytes: nonce (12 bytes) + ciphertext (includes tag)
        """
        if len(key) != 32:
            raise ValueError("Key must be 32 bytes for ChaCha20Poly1305")

        chacha = ChaCha20Poly1305(key)
        nonce = os.urandom(12)
        ciphertext = chacha.encrypt(nonce, plaintext, associated_data)

        return nonce + ciphertext

    def decrypt(
        self, ciphertext: bytes, key: bytes, associated_data: bytes | None = None
    ) -> bytes:
        """
        Decrypts ciphertext.

        Args:
            ciphertext: nonce (12 bytes) + ciphertext/tag
            key: 32-byte secret key
            associated_data: Optional AAD

        Returns:
            bytes: Original plaintext
        """
        if len(key) != 32:
            raise ValueError("Key must be 32 bytes for ChaCha20Poly1305")

        if len(ciphertext) < 28:  # 12 nonce + 16 tag min
            raise ValueError("Ciphertext too short")

        nonce = ciphertext[:12]
        actual_ciphertext = ciphertext[12:]
        chacha = ChaCha20Poly1305(key)

        return chacha.decrypt(nonce, actual_ciphertext, associated_data)


class AsymmetricCipher:
    """Handles asymmetric encryption using RSA-OAEP."""

    def encrypt(self, plaintext: bytes, public_key: bytes) -> bytes:
        """
        Encrypts plaintext using RSA public key.

        Args:
            plaintext: Data to encrypt
            public_key: PEM encoded public key bytes

        Returns:
            bytes: Ciphertext
        """
        key_obj = serialization.load_pem_public_key(public_key)

        if not isinstance(key_obj, rsa.RSAPublicKey):
            raise ValueError("Only RSA keys are supported for AsymmetricCipher")

        ciphertext = key_obj.encrypt(
            plaintext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        return ciphertext

    def decrypt(self, ciphertext: bytes, private_key: bytes) -> bytes:
        """
        Decrypts ciphertext using RSA private key.

        Args:
            ciphertext: Encrypted data
            private_key: PEM encoded private key bytes

        Returns:
            bytes: Plaintext
        """
        key_obj = serialization.load_pem_private_key(private_key, password=None)

        if not isinstance(key_obj, rsa.RSAPrivateKey):
            raise ValueError("Only RSA keys are supported for AsymmetricCipher")

        plaintext = key_obj.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        return plaintext
