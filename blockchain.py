from block import Block
from message import Message
from structs import MessageContent, PublicKey, Transaction
from wallet import Wallet


class Blockchain:
    def __init__(self, difficulty: int) -> None: ...

    def create_transaction(
        self,
        sender_wallet: Wallet,
        recipient_pubkey: PublicKey,
        message: MessageContent,
    ) -> Transaction: ...

    def add_transaction(self, tx: Transaction) -> bool: ...

    def mine_block(self, miner_wallet: Wallet) -> Block: ...

    def is_valid(self) -> bool: ...

    def get_messages_to(self, pubkey: PublicKey) -> list[Message]: ...

    def get_chain(self) -> list[Block]: ...
