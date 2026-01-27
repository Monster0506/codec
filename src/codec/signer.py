from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, padding, rsa
from cryptography.exceptions import InvalidSignature


class Signer:
    """Signs and verifies messages using Ed25519 or RSA-PSS."""

    def sign(self, message: bytes, private_key: bytes) -> bytes:
        """
        Signs a message using the private key.

        Args:
            message: The message to sign.
            private_key: PEM encoded private key bytes.

        Returns:
            bytes: The signature.
        """
        key_obj = serialization.load_pem_private_key(private_key, password=None)

        if isinstance(key_obj, ed25519.Ed25519PrivateKey):
            return key_obj.sign(message)
        elif isinstance(key_obj, rsa.RSAPrivateKey):
            return key_obj.sign(
                message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )
        else:
            raise ValueError("Unsupported key type for signing")

    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        """
        Verifies a signature.

        Args:
            message: The original message.
            signature: The signature to verify.
            public_key: PEM encoded public key bytes.

        Returns:
            bool: True if valid, False otherwise.
        """
        key_obj = serialization.load_pem_public_key(public_key)

        try:
            if isinstance(key_obj, ed25519.Ed25519PublicKey):
                key_obj.verify(signature, message)
                return True
            elif isinstance(key_obj, rsa.RSAPublicKey):
                key_obj.verify(
                    signature,
                    message,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH,
                    ),
                    hashes.SHA256(),
                )
                return True
            else:
                raise ValueError("Unsupported key type for verification")
        except InvalidSignature:
            return False
