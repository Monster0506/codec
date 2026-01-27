import asyncio
import websockets
from websockets.server import serve
from websockets.client import connect
from codec.message import Message
from codec.transport.base import MessageTransport
from codec.errors import SerializationError

class WebSocketTransport(MessageTransport):
    def __init__(self, host: str = "0.0.0.0", port: int = 8765):
        self.host = host
        self.port = port
        self.queue: asyncio.Queue[Message] = asyncio.Queue()
        self.server = None
        self.stop_event = asyncio.Event()

    async def start_server(self) -> None:
        """Starts the WebSocket server."""
        self.stop_event.clear()
        self.server = await serve(self._handle_connection, self.host, self.port)

    async def stop_server(self) -> None:
        """Stops the WebSocket server."""
        if self.server:
            self.server.close()
            await self.server.wait_closed()
            self.server = None

    async def _handle_connection(self, websocket):
        """Internal handler for incoming WebSocket connections."""
        try:
            async for message_data in websocket:
                try:
                    # message_data can be str or bytes. We expect bytes serialize.
                    if isinstance(message_data, str):
                        message_data = message_data.encode("utf-8")
                    
                    message = Message.deserialize(message_data)
                    await self.queue.put(message)
                    
                    await websocket.send("OK")
                except Exception as e:
                    await websocket.send(f"Error: {str(e)}")
        except Exception:
            # Connection closed/error
            pass

    async def send(self, message: Message, endpoint: str) -> None:
        """
        Sends a message to the WebSocket endpoint.
        
        Args:
            message: The Message to send.
            endpoint: The full WS URL (e.g., ws://localhost:8765)
        """
        data = message.serialize()
        async with connect(endpoint) as websocket:
            await websocket.send(data)
            try:
                await asyncio.wait_for(websocket.recv(), timeout=2.0)
            except asyncio.TimeoutError:
                pass

    async def receive(self) -> Message:
        """
        Waits for and returns the next received message from the queue.
        Requires start_server() to have been called.
        """
        return await self.queue.get()
