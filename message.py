from dataclasses import dataclass

from structs import (
    BlockIndex,
    MessageContent,
    PrivateKey,
    PublicKey,
    Timestamp,
    Transaction,
)


@dataclass
class Message:
    transaction: Transaction
    block_index: BlockIndex
    block_timestamp: Timestamp

    def decrypt(self, private_key: PrivateKey) -> MessageContent: ...

    @property
    def sender(self) -> PublicKey: ...

    @property
    def timestamp(self) -> Timestamp: ...
