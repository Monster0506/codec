import asyncio
import pytest
from codec.transport.websocket import WebSocketTransport
from codec.message import Message

@pytest.mark.asyncio
async def test_websocket_transport_send_receive():
    # Setup Server
    server_transport = WebSocketTransport(host="127.0.0.1", port=8766)
    await server_transport.start_server()
    
    # Setup Client
    client_transport = WebSocketTransport() 
    
    try:
        # Create a dummy message
        msg = Message(
            payload=b"Hello WebSocket",
            sender_id="alice",
            recipient_id="bob",
            encrypted=False,
            signed=False
        )
        
        # Send message
        endpoint = "ws://127.0.0.1:8766"
        await client_transport.send(msg, endpoint)
        
        # Receive message on server
        received_msg = await asyncio.wait_for(server_transport.receive(), timeout=2.0)
        
        assert received_msg.payload == b"Hello WebSocket"
        assert received_msg.sender_id == "alice"
        
    finally:
        await server_transport.stop_server()

@pytest.mark.asyncio
async def test_websocket_transport_invalid_message():
    server_transport = WebSocketTransport(host="127.0.0.1", port=8767)
    await server_transport.start_server()
    
    import websockets
    endpoint = "ws://127.0.0.1:8767"
    
    try:
        # Send garbage data manually
        async with websockets.connect(endpoint) as websocket:
            await websocket.send(b"garbage")
            response = await websocket.recv()
            assert "Error" in response

    finally:
        await server_transport.stop_server()
