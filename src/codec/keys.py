from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from cryptography.hazmat.primitives.asymmetric.types import (
    PrivateKeyTypes,
    PublicKeyTypes,
)


@dataclass
class KeyPair:
    """Holds public/private keypair"""

    public_key: bytes
    private_key: bytes
    algorithm: str


class KeyStore:
    """Manages key storage and retrieval"""

    def generate_keypair(self, algorithm: Literal["RSA-4096", "Ed25519"]) -> KeyPair:
        """Generates a new keypair for the specified algorithm."""
        private_key: PrivateKeyTypes
        public_key: PublicKeyTypes

        if algorithm == "RSA-4096":
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=4096,
            )
        elif algorithm == "Ed25519":
            private_key = ed25519.Ed25519PrivateKey.generate()
        else:
            raise ValueError(f"Unsupported algorithm: {algorithm}")

        public_key = private_key.public_key()

        # Serialize to bytes for the KeyPair struct (internal representation)
        # We store the raw PEM bytes in the KeyPair for easy transport/storage if needed,
        # or we could store the objects. The prompt asked for `bytes`.
        # Let's standardize on PEM format for the bytes in KeyPair.
        priv_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        pub_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        return KeyPair(
            public_key=pub_bytes,
            private_key=priv_bytes,
            algorithm=algorithm,
        )

    def save_keypair(
        self, keypair: KeyPair, path: str, password: str | None = None
    ) -> None:
        """Saves a keypair to disk.

        The private key is saved to `path` (encrypted if password provided).
        The public key is saved to `path.pub`.
        """
        base_path = Path(path)

        # Load the bytes back to object to re-serialize with potential encryption
        # This is a bit redundant but ensures checking valid bytes before save
        private_key = serialization.load_pem_private_key(
            keypair.private_key, password=None
        )

        encryption_algo = (
            serialization.BestAvailableEncryption(password.encode())
            if password
            else serialization.NoEncryption()
        )

        # Save Private
        with open(base_path, "wb") as f:
            f.write(
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=encryption_algo,
                )
            )

        # Save Public
        with open(base_path.with_suffix(".pub"), "wb") as f:
            f.write(keypair.public_key)

    def load_keypair(
        self, private_key_path: str, password: str | None = None
    ) -> KeyPair:
        """Loads a keypair from disk."""
        priv_path = Path(private_key_path)

        with open(priv_path, "rb") as f:
            priv_data = f.read()

        private_key = serialization.load_pem_private_key(
            priv_data, password=password.encode() if password else None
        )

        # Determine algorithm
        algo = "Unknown"
        if isinstance(private_key, rsa.RSAPrivateKey):
            algo = "RSA-4096"  # Assumption based on generation, could check size
        elif isinstance(private_key, ed25519.Ed25519PrivateKey):
            algo = "Ed25519"

        public_key = private_key.public_key()

        # Get raw bytes
        priv_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        pub_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        return KeyPair(
            public_key=pub_bytes,
            private_key=priv_bytes,
            algorithm=algo,
        )

    def derive_public_key(self, private_key: bytes) -> bytes:
        """Derives the public key bytes from a private key PEM."""
        priv_obj = serialization.load_pem_private_key(private_key, password=None)
        return priv_obj.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
