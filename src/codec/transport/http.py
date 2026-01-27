import asyncio
import aiohttp
from aiohttp import web
from codec.message import Message
from codec.transport.base import MessageTransport
from codec.errors import SerializationError

class HTTPTransport(MessageTransport):
    def __init__(self, host: str = "0.0.0.0", port: int = 8080):
        self.host = host
        self.port = port
        self.queue: asyncio.Queue[Message] = asyncio.Queue()
        self.app = web.Application()
        self.app.router.add_post("/messages", self._handle_message)
        self.runner: web.AppRunner | None = None
        self.site: web.TCPSite | None = None

    async def start_server(self) -> None:
        """Starts the HTTP server to listen for messages."""
        self.runner = web.AppRunner(self.app)
        await self.runner.setup()
        self.site = web.TCPSite(self.runner, self.host, self.port)
        await self.site.start()

    async def stop_server(self) -> None:
        """Stops the HTTP server."""
        if self.site:
            await self.site.stop()
        if self.runner:
            await self.runner.cleanup()

    async def _handle_message(self, request: web.Request) -> web.Response:
        """Internal handler for incoming POST requests."""
        try:
            data = await request.read()
            message = Message.deserialize(data)
            await self.queue.put(message)
            return web.Response(text="OK")
        except Exception as e:
            return web.Response(status=400, text=f"Invalid message: {str(e)}")

    async def send(self, message: Message, endpoint: str) -> None:
        """
        Sends a message to the HTTP endpoint.
        
        Args:
            message: The Message to send.
            endpoint: The full URL (e.g., http://localhost:8080/messages)
        """
        data = message.serialize()
        async with aiohttp.ClientSession() as session:
            async with session.post(endpoint, data=data) as response:
                response.raise_for_status()

    async def receive(self) -> Message:
        """
        Waits for and returns the next received message from the queue.
        Requires start_server() to have been called.
        """
        return await self.queue.get()
