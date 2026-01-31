# Codec

A Python library for secure messaging using hybrid encryption (RSA + ChaCha20-Poly1305) and digital signatures (Ed25519/RSA).

## Features

- **Hybrid Encryption**: Encrypt-then-MAC using ChaCha20-Poly1305 for content and RSA-OAEP for session keys.
- **Signatures**: Verifies message origin and integrity using Ed25519 or RSA-PSS.
- **Transport**: Includes basic implementations for HTTP (`aiohttp`) and WebSocket (`websockets`) transport.
- **forward Secrecy**: Supports ephemeral session establishment via X25519.

## Installation

```bash
uv add codec
# or
pip install codec
```

## Quick Start

```python
import asyncio
from codec.keys import KeyStore
from codec.messenger import SecureMessenger
from codec.cipher import Cipher
from codec.signer import Signer
from codec.transport.websocket import WebSocketTransport

async def main():
    # 1. Setup Identities
    keystore = KeyStore()
    alice = keystore.generate_keypair("RSA-4096")
    bob = keystore.generate_keypair("RSA-4096")

    # 2. Initialize Messenger
    messenger = SecureMessenger(keystore, Cipher(), Signer())

    # 3. Send a Message
    # In a real app, you would start a transport server here.
    # We will just simulate the message creation.
    
    message = messenger.send(
        plaintext=b"Hello, secure world!",
        recipient_public_key=bob.public_key,
        sender_private_key=alice.private_key,
        sender_id="alice",
        recipient_id="bob"
    )

    print(f"Encrypted payload: {message.payload[:20]}...")

    # 4. Receive & Decrypt
    plaintext = messenger.receive(
        message=message,
        recipient_private_key=bob.private_key,
        sender_public_key=alice.public_key
    )

    print(f"Decrypted: {plaintext.decode()}")

if __name__ == "__main__":
    asyncio.run(main())
```

## License

MIT
