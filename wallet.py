from dataclasses import dataclass

from structs import PrivateKey, PublicKey, Signature


@dataclass
class Wallet:
    public_key: PublicKey
    private_key: PrivateKey

    @classmethod
    def generate(cls) -> Wallet: ...

    @classmethod
    def from_private_key(cls, key: PrivateKey) -> Wallet: ...

    def sign(self, data: bytes) -> Signature: ...
