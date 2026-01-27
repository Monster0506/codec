import pytest
from codec.messenger import SecureMessenger
from codec.keys import KeyStore
from codec.cipher import Cipher
from codec.signer import Signer
from codec.errors import CryptoError, VerificationError
import json
import base64


@pytest.fixture
def keystore():
    return KeyStore()


@pytest.fixture
def messenger(keystore):
    return SecureMessenger(keystore=keystore, cipher=Cipher(), signer=Signer())


def test_secure_messenger_send_receive_flow(keystore, messenger):
    # Setup identities
    alice_keys = keystore.generate_keypair("RSA-4096")
    bob_keys = keystore.generate_keypair("RSA-4096")

    plaintext = b"Secret Message for Bob"

    # Alice sends to Bob
    message = messenger.send(
        plaintext=plaintext,
        recipient_public_key=bob_keys.public_key,
        sender_private_key=alice_keys.private_key,
        sender_id="alice",
        recipient_id="bob",
    )

    assert message.sender_id == "alice"
    assert message.recipient_id == "bob"
    assert message.encrypted is True
    assert message.signed is True

    # Bob receives from Alice
    received_plaintext = messenger.receive(
        message=message,
        recipient_private_key=bob_keys.private_key,
        sender_public_key=alice_keys.public_key,
    )

    assert received_plaintext == plaintext


def test_receive_tampered_signature(keystore, messenger):
    alice_keys = keystore.generate_keypair("RSA-4096")
    bob_keys = keystore.generate_keypair("RSA-4096")

    message = messenger.send(
        plaintext=b"Data",
        recipient_public_key=bob_keys.public_key,
        sender_private_key=alice_keys.private_key,
        sender_id="alice",
        recipient_id="bob",
    )

    payload_dict = json.loads(message.payload.decode("utf-8"))
    sig_bytes = base64.b64decode(payload_dict["signature"])

    bad_sig = bytearray(sig_bytes)
    bad_sig[0] ^= 0xFF

    payload_dict["signature"] = base64.b64encode(bad_sig).decode("ascii")
    message.payload = json.dumps(payload_dict).encode("utf-8")

    with pytest.raises(VerificationError, match="Invalid message signature"):
        messenger.receive(
            message=message,
            recipient_private_key=bob_keys.private_key,
            sender_public_key=alice_keys.public_key,
        )


def test_receive_tampered_encrypted_content(keystore, messenger):
    alice_keys = keystore.generate_keypair("RSA-4096")
    bob_keys = keystore.generate_keypair("RSA-4096")

    message = messenger.send(
        plaintext=b"Data",
        recipient_public_key=bob_keys.public_key,
        sender_private_key=alice_keys.private_key,
        sender_id="alice",
        recipient_id="bob",
    )

    payload_dict = json.loads(message.payload.decode("utf-8"))
    content_bytes = base64.b64decode(payload_dict["content"])

    bad_content = bytearray(content_bytes)
    bad_content[10] ^= 0xFF

    payload_dict["content"] = base64.b64encode(bad_content).decode("ascii")
    message.payload = json.dumps(payload_dict).encode("utf-8")

    with pytest.raises(VerificationError, match="Invalid message signature"):
        messenger.receive(
            message=message,
            recipient_private_key=bob_keys.private_key,
            sender_public_key=alice_keys.public_key,
        )


def test_receive_wrong_recipient_key(keystore, messenger):
    alice_keys = keystore.generate_keypair("RSA-4096")
    bob_keys = keystore.generate_keypair("RSA-4096")
    eve_keys = keystore.generate_keypair("RSA-4096")

    message = messenger.send(
        plaintext=b"For Bob",
        recipient_public_key=bob_keys.public_key,
        sender_private_key=alice_keys.private_key,
        sender_id="alice",
        recipient_id="bob",
    )

    with pytest.raises((CryptoError, ValueError)):
        messenger.receive(
            message=message,
            recipient_private_key=eve_keys.private_key,
            sender_public_key=alice_keys.public_key,
        )
