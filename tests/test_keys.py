import os
import pytest
from cryptography.hazmat.primitives import serialization
from codec.keys import KeyStore, KeyPair


@pytest.fixture
def keystore():
    return KeyStore()


def test_generate_rsa_keypair(keystore):
    keypair = keystore.generate_keypair("RSA-4096")
    assert keypair.algorithm == "RSA-4096"
    assert keypair.private_key.startswith(b"-----BEGIN PRIVATE KEY-----")
    assert keypair.public_key.startswith(b"-----BEGIN PUBLIC KEY-----")


def test_generate_ed25519_keypair(keystore):
    keypair = keystore.generate_keypair("Ed25519")
    assert keypair.algorithm == "Ed25519"
    assert keypair.private_key.startswith(b"-----BEGIN PRIVATE KEY-----")
    assert keypair.public_key.startswith(b"-----BEGIN PUBLIC KEY-----")


def test_save_and_load_keypair_unencrypted(keystore, tmp_path):
    keypair = keystore.generate_keypair("Ed25519")
    priv_path = tmp_path / "test_key"

    keystore.save_keypair(keypair, str(priv_path))

    loaded_keypair = keystore.load_keypair(str(priv_path))

    assert loaded_keypair.public_key == keypair.public_key
    assert loaded_keypair.private_key == keypair.private_key
    assert loaded_keypair.algorithm == "Ed25519"


def test_save_and_load_keypair_encrypted(keystore, tmp_path):
    keypair = keystore.generate_keypair("RSA-4096")
    priv_path = tmp_path / "test_key_enc"
    password = "secret_password"

    keystore.save_keypair(keypair, str(priv_path), password=password)

    loaded_keypair = keystore.load_keypair(str(priv_path), password=password)

    assert loaded_keypair.public_key == keypair.public_key
    assert loaded_keypair.private_key == keypair.private_key
    with pytest.raises(ValueError):
        keystore.load_keypair(str(priv_path), password="wrong")


def test_derive_public_key(keystore):
    keypair = keystore.generate_keypair("Ed25519")
    derived_pub = keystore.derive_public_key(keypair.private_key)
    assert derived_pub == keypair.public_key
