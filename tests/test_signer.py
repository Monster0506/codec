import pytest
from codec.signer import Signer
from codec.keys import KeyStore

@pytest.fixture
def keystore():
    return KeyStore()

@pytest.fixture
def signer():
    return Signer()

def test_ed25519_sign_verify(keystore, signer):
    keypair = keystore.generate_keypair("Ed25519")
    message = b"Hello Ed25519"
    
    signature = signer.sign(message, keypair.private_key)
    assert len(signature) > 0
    
    valid = signer.verify(message, signature, keypair.public_key)
    assert valid is True

def test_rsa_sign_verify(keystore, signer):
    keypair = keystore.generate_keypair("RSA-4096")
    message = b"Hello RSA"
    
    signature = signer.sign(message, keypair.private_key)
    assert len(signature) > 0
    
    valid = signer.verify(message, signature, keypair.public_key)
    assert valid is True

def test_verify_tampered_message(keystore, signer):
    keypair = keystore.generate_keypair("Ed25519")
    message = b"Original Message"
    signature = signer.sign(message, keypair.private_key)
    
    valid = signer.verify(b"Tampered Message", signature, keypair.public_key)
    assert valid is False

def test_verify_tampered_signature(keystore, signer):
    keypair = keystore.generate_keypair("Ed25519")
    message = b"Message"
    signature = signer.sign(message, keypair.private_key)
    
    # Flip last byte
    tampered_sig = signature[:-1] + bytes([signature[-1] ^ 0xFF])
    
    valid = signer.verify(message, tampered_sig, keypair.public_key)
    assert valid is False

def test_verify_wrong_key(keystore, signer):
    keypair1 = keystore.generate_keypair("Ed25519")
    keypair2 = keystore.generate_keypair("Ed25519")
    message = b"Message"
    
    signature = signer.sign(message, keypair1.private_key)
    
    # Verify with wrong public key
    valid = signer.verify(message, signature, keypair2.public_key)
    assert valid is False
