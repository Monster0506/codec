import json
import base64
from dataclasses import dataclass, asdict
from typing import Any
from codec.errors import SerializationError


@dataclass
class Message:
    """Represents a cryptographic message."""

    payload: bytes
    sender_id: str
    recipient_id: str
    encrypted: bool = False
    signed: bool = False

    def serialize(self) -> bytes:
        """Serializes the message to a JSON byte string."""
        try:
            data = {
                "sender_id": self.sender_id,
                "recipient_id": self.recipient_id,
                "encrypted": self.encrypted,
                "signed": self.signed,
                "payload": base64.b64encode(self.payload).decode("ascii"),
            }
            return json.dumps(data).encode("utf-8")
        except Exception as e:
            raise SerializationError(f"Failed to serialize message: {e}") from e

    @classmethod
    def deserialize(cls, data: bytes) -> "Message":
        """Deserializes a message from a JSON byte string."""
        try:
            json_data = json.loads(data.decode("utf-8"))

            required = {"sender_id", "recipient_id", "payload", "encrypted", "signed"}
            if not required.issubset(json_data.keys()):
                raise ValueError("Missing required fields in message data")

            return cls(
                sender_id=json_data["sender_id"],
                recipient_id=json_data["recipient_id"],
                encrypted=json_data["encrypted"],
                signed=json_data["signed"],
                payload=base64.b64decode(json_data["payload"]),
            )
        except Exception as e:
            raise SerializationError(f"Failed to deserialize message: {e}") from e
