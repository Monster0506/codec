import time
from dataclasses import dataclass


@dataclass
class _Key:
    key_bytes: bytes

    def __str__(self) -> str:
        return self.key_bytes.hex()

    @classmethod
    def from_hex(cls, hex_str: str) -> _Key:
        return cls(bytes.fromhex(hex_str))


class PublicKey(_Key): ...


class PrivateKey(_Key): ...


@dataclass
class EncryptedMessage:
    ciphertext: bytes

    def __str__(self) -> str:
        return self.ciphertext.hex()

    @classmethod
    def from_hex(cls, hex_str: str) -> EncryptedMessage:
        return cls(bytes.fromhex(hex_str))


@dataclass
class Signature:
    sig_bytes: bytes

    def __str__(self) -> str:
        return self.sig_bytes.hex()

    @classmethod
    def from_hex(cls, hex_str: str) -> Signature:
        return cls(bytes.fromhex(hex_str))


@dataclass
class Timestamp:
    unix_seconds: int

    @classmethod
    def now(cls) -> Timestamp:
        return cls(int(time.time()))


@dataclass
class Transaction:
    sender_pubkey: PublicKey
    recipient_pubkey: PrivateKey
    encrypted_message: EncryptedMessage
    signature: Signature
    timestamp: Timestamp


@dataclass
class Hash:
    hash_bytes: bytes

    def __str__(self) -> str:
        return self.hash_bytes.hex()

    @classmethod
    def from_hex(cls, hex_str: str) -> Hash:
        return cls(bytes.fromhex(hex_str))

