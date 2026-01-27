import asyncio
import pytest
from aiohttp import web
from codec.transport.http import HTTPTransport
from codec.message import Message

@pytest.mark.asyncio
async def test_http_transport_send_receive():
    # Setup Server
    server_transport = HTTPTransport(host="127.0.0.1", port=8081)
    await server_transport.start_server()
    
    # Setup Client
    client_transport = HTTPTransport() # Port doesn't matter for sending
    
    try:
        # Create a dummy message
        msg = Message(
            payload=b"Hello HTTP",
            sender_id="alice",
            recipient_id="bob",
            encrypted=False,
            signed=False
        )
        
        # Send message
        endpoint = "http://127.0.0.1:8081/messages"
        await client_transport.send(msg, endpoint)
        
        # Receive message on server
        received_msg = await asyncio.wait_for(server_transport.receive(), timeout=2.0)
        
        assert received_msg.payload == b"Hello HTTP"
        assert received_msg.sender_id == "alice"
        
    finally:
        await server_transport.stop_server()
        await client_transport.stop_server() # Just in case

@pytest.mark.asyncio
async def test_http_transport_invalid_message():
    server_transport = HTTPTransport(host="127.0.0.1", port=8082)
    await server_transport.start_server()
    
    import aiohttp
    endpoint = "http://127.0.0.1:8082/messages"
    
    try:
        # Send garbage data manually using aiohttp to simulate bad request
        async with aiohttp.ClientSession() as session:
            async with session.post(endpoint, data=b"garbage") as resp:
                assert resp.status == 400
                text = await resp.text()
                assert "Invalid message" in text

    finally:
        await server_transport.stop_server()
