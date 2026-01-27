from dataclasses import dataclass

from structs import BlockIndex, Hash, MerkleRoot, Nonce, Timestamp, Transaction


@dataclass
class Block:
    index: BlockIndex
    timestamp: Timestamp
    transactions: list[Transaction]
    previous_hash: Hash
    current_hash: Hash
    nonce: Nonce
    merkle_root: MerkleRoot

    def is_valid(self) -> bool: ...
