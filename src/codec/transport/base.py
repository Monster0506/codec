from abc import ABC, abstractmethod
from codec.message import Message

class MessageTransport(ABC):
    """Abstract base class for message delivery."""

    @abstractmethod
    async def send(self, message: Message, endpoint: str) -> None:
        """
        Sends a message to the specified endpoint.
        
        Args:
            message: The Message object to send.
            endpoint: The destination URL or address.
        """
        pass

    @abstractmethod
    async def receive(self) -> Message:
        """
        Receives a message.
        
        Returns:
            Message: The received message.
        """
        pass
