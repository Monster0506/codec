import pytest
from codec.session import EncryptedSession
from codec.keys import KeyStore
from codec.errors import CryptoError


@pytest.fixture
def keystore():
    return KeyStore()


def test_session_handshake_and_encryption(keystore):
    # Identities (not strictly used for handshake auth in this basic version, but required by API)
    alice_identity = keystore.generate_keypair("Ed25519")
    bob_identity = keystore.generate_keypair("Ed25519")

    # Alice initiates
    alice_session = EncryptedSession(alice_identity, bob_identity.public_key)
    alice_handshake = alice_session.establish()

    # Bob responds
    bob_session = EncryptedSession(bob_identity, alice_identity.public_key)
    bob_handshake = bob_session.establish()

    # Both process peer's handshake
    alice_session.process_handshake(bob_handshake)
    bob_session.process_handshake(alice_handshake)

    assert alice_session.session_key is not None
    assert bob_session.session_key is not None
    assert alice_session.session_key == bob_session.session_key

    # Test Encryption
    plaintext = b"Session Message"
    ciphertext = alice_session.encrypt_message(plaintext)

    decrypted = bob_session.decrypt_message(ciphertext)
    assert decrypted == plaintext

    # Bidirectional
    response = bob_session.encrypt_message(b"Reply")
    assert alice_session.decrypt_message(response) == b"Reply"


def test_session_not_established():
    ks = KeyStore()
    kp = ks.generate_keypair("Ed25519")
    session = EncryptedSession(kp, kp.public_key)

    with pytest.raises(CryptoError, match="Session not established"):
        session.encrypt_message(b"fail")

    with pytest.raises(CryptoError, match="Session not established"):
        session.decrypt_message(b"fail")
