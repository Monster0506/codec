from dataclasses import dataclass
from time import time


@dataclass
class PublicKey:
    key_bytes: bytes

    def __str__(self) -> str:
        return self.key_bytes.hex()

    @classmethod
    def from_hex(cls, hex_str: str) -> PublicKey:
        return cls(bytes.fromhex(hex_str))


@dataclass
class PrivateKey:
    key_bytes: bytes

    def __str__(self) -> str:
        return self.key_bytes.hex()

    @classmethod
    def from_hex(cls, hex_str: str) -> PrivateKey:
        return cls(bytes.fromhex(hex_str))


@dataclass
class Signature:
    sig_bytes: bytes

    def __bytes__(self) -> bytes:
        return self.sig_bytes


@dataclass
class Hash:
    hash_bytes: bytes

    def __str__(self) -> str:
        return self.hash_bytes.hex()


@dataclass
class MerkleRoot:
    root_bytes: bytes


@dataclass
class EncryptedMessage:
    ciphertext: bytes


@dataclass
class MessageContent:
    plaintext: str

    def to_bytes(self) -> bytes:
        return self.plaintext.encode("utf-8")


@dataclass
class Timestamp:
    unix_seconds: int

    @classmethod
    def now(cls) -> Timestamp:
        return cls(int(time()))


@dataclass
class BlockIndex:
    value: int


@dataclass
class Nonce:
    value: int


@dataclass
class Transaction:
    sender: PublicKey
    recipient: PublicKey
    encrypted_message: EncryptedMessage
    signature: Signature
    timestamp: Timestamp

