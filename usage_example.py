import asyncio
import os
import shutil
from codec.keys import KeyStore
from codec.cipher import Cipher
from codec.signer import Signer
from codec.messenger import SecureMessenger
from codec.transport.http import HTTPTransport
from codec.transport.websocket import WebSocketTransport

async def main():
    # 0. Cleanup previous run
    if os.path.exists("alice_key"): os.remove("alice_key")
    if os.path.exists("alice_key.pub"): os.remove("alice_key.pub")
    if os.path.exists("bob_key"): os.remove("bob_key")
    if os.path.exists("bob_key.pub"): os.remove("bob_key.pub")

    print("--- 1. Setup Identities ---")
    keystore = KeyStore()
    
    # Generate Alice's keys
    print("Generating Alice's keys...")
    alice_keypair = keystore.generate_keypair("RSA-4096")
    keystore.save_keypair(alice_keypair, "alice_key", password="alice_password")
    
    # Generate Bob's keys
    print("Generating Bob's keys...")
    bob_keypair = keystore.generate_keypair("RSA-4096")
    keystore.save_keypair(bob_keypair, "bob_key", password="bob_password")
    
    # Load keys (simulating separate parties)
    alice_loaded = keystore.load_keypair("alice_key", password="alice_password")
    bob_loaded = keystore.load_keypair("bob_key", password="bob_password")
    
    # Exchange public keys (in reality this happens out of band)
    alice_pub = alice_loaded.public_key
    bob_pub = bob_loaded.public_key
    
    print("--- 2. Initialize Messenger ---")
    # Alice's messenger
    alice_messenger = SecureMessenger(
        keystore=KeyStore(),
        cipher=Cipher(),
        signer=Signer()
    )
    
    # Bob's messenger
    bob_messenger = SecureMessenger(
        keystore=KeyStore(),
        cipher=Cipher(),
        signer=Signer()
    )
    
    print("--- 3. Setup Transport ---")
    # Bob listens on HTTP
    bob_transport = HTTPTransport(host="127.0.0.1", port=8090)
    await bob_transport.start_server()
    print("Bob listening on http://127.0.0.1:8090/messages")
    
    # Alice listens on WebSockets
    alice_transport = WebSocketTransport(host="127.0.0.1", port=8765)
    await alice_transport.start_server()
    print("Alice listening on ws://127.0.0.1:8765")
    
    try:
        # --- Flow 1: Alice -> Bob (HTTP) ---
        print("\n--- 4a. Alice Sends Message to Bob (HTTP) ---")
        plaintext_to_bob = b"Hello Bob! This is over HTTP."
        
        msg_to_bob = alice_messenger.send(
            plaintext=plaintext_to_bob,
            recipient_public_key=bob_pub,
            sender_private_key=alice_loaded.private_key,
            sender_id="alice",
            recipient_id="bob"
        )
        
        # Alice needs an HTTP transport client to reach Bob (who is on HTTP)
        http_client = HTTPTransport()
        await http_client.send(msg_to_bob, "http://127.0.0.1:8090/messages")
        print("Message sent to Bob via HTTP")
        
        # Bob receives
        received_at_bob = await bob_transport.receive()
        decrypted_at_bob = bob_messenger.receive(
            message=received_at_bob,
            recipient_private_key=bob_loaded.private_key,
            sender_public_key=alice_pub
        )
        print(f"Bob received: {decrypted_at_bob}")
        assert decrypted_at_bob == plaintext_to_bob

        # --- Flow 2: Bob -> Alice (WebSocket) ---
        print("\n--- 4b. Bob Sends Message to Alice (WebSocket) ---")
        plaintext_to_alice = b"Hello Alice! This is over WebSockets."
        
        msg_to_alice = bob_messenger.send(
            plaintext=plaintext_to_alice,
            recipient_public_key=alice_pub,
            sender_private_key=bob_loaded.private_key,
            sender_id="bob",
            recipient_id="alice"
        )
        
        # Bob needs a WebSocket transport client to reach Alice (who is on WS)
        ws_client = WebSocketTransport()
        await ws_client.send(msg_to_alice, "ws://127.0.0.1:8765")
        print("Message sent to Alice via WebSocket")
        
        # Alice receives
        received_at_alice = await alice_transport.receive()
        print(f"Alice received: {received_at_alice}")
        decrypted_at_alice = alice_messenger.receive(
            message=received_at_alice,
            recipient_private_key=alice_loaded.private_key,
            sender_public_key=bob_pub
        )
        print(f"Alice received: {decrypted_at_alice}")
        assert decrypted_at_alice == plaintext_to_alice
        
        print("\nSUCCESS: Mixed transport flow verified!")
        
    finally:
        await bob_transport.stop_server()
        await alice_transport.stop_server()

if __name__ == "__main__":
    asyncio.run(main())
