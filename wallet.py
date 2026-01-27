from dataclasses import dataclass

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from structs import PrivateKey, PublicKey, Signature


@dataclass
class Wallet:
    public_key: PublicKey
    private_key: PrivateKey

    @classmethod
    def generate(cls) -> Wallet:
        privkey_obj = ed25519.Ed25519PrivateKey.generate()
        priv_bytes = privkey_obj.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        pubkey_obj = privkey_obj.public_key()
        pub_bytes = pubkey_obj.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

        return cls(public_key=PublicKey(pub_bytes), private_key=PrivateKey(priv_bytes))

    @classmethod
    def from_private_key(cls, key: PrivateKey) -> Wallet:
        privkey_obj = ed25519.Ed25519PrivateKey.from_private_bytes(key.key_bytes)
        pubkey_obj = privkey_obj.public_key()
        pub_bytes = pubkey_obj.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

        return cls(public_key=PublicKey(pub_bytes), private_key=key)

    def sign(self, data: bytes) -> Signature:
        privkey_obj = ed25519.Ed25519PrivateKey.from_private_bytes(
            self.private_key.key_bytes
        )
        sig = privkey_obj.sign(data)
        return Signature(sig)
