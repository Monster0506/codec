import os
import pytest
from codec.cipher import Cipher, AsymmetricCipher
from codec.keys import KeyStore

@pytest.fixture
def keystore():
    return KeyStore()

@pytest.fixture
def rsa_keypair(keystore):
    return keystore.generate_keypair("RSA-4096")

def test_symmetric_encryption_decryption():
    cipher = Cipher()
    key = os.urandom(32)
    plaintext = b"Secret Message"
    aad = b"header_data"

    # Encrypt
    encrypted = cipher.encrypt(plaintext, key, associated_data=aad)
    assert encrypted != plaintext
    
    # Decrypt
    decrypted = cipher.decrypt(encrypted, key, associated_data=aad)
    assert decrypted == plaintext

def test_symmetric_encryption_invalid_key():
    cipher = Cipher()
    key = os.urandom(16) # Invalid length
    with pytest.raises(ValueError, match="Key must be 32 bytes"):
        cipher.encrypt(b"data", key)

def test_symmetric_decryption_tampered_data():
    cipher = Cipher()
    key = os.urandom(32)
    plaintext = b"Secret Message"
    encrypted = cipher.encrypt(plaintext, key)
    
    # Tamper with the ciphertext (last byte)
    tampered = encrypted[:-1] + bytes([(encrypted[-1] ^ 0xFF)])
    
    with pytest.raises(Exception): # InvalidTag
        cipher.decrypt(tampered, key)

def test_asymmetric_encryption_decryption(rsa_keypair):
    cipher = AsymmetricCipher()
    plaintext = b"Asymmetric Secret"
    
    # Encrypt with Public Key
    encrypted = cipher.encrypt(plaintext, rsa_keypair.public_key)
    assert encrypted != plaintext
    
    # Decrypt with Private Key
    decrypted = cipher.decrypt(encrypted, rsa_keypair.private_key)
    assert decrypted == plaintext

def test_asymmetric_bad_keys(keystore):
    cipher = AsymmetricCipher()
    # Use Ed25519 key (invalid for this cipher which expects RSA)
    ed_key = keystore.generate_keypair("Ed25519")
    
    with pytest.raises(ValueError, match="Only RSA keys are supported"):
        cipher.encrypt(b"data", ed_key.public_key)

    with pytest.raises(ValueError, match="Only RSA keys are supported"):
        cipher.decrypt(b"data", ed_key.private_key)
