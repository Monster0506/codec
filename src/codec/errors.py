class CodecError(Exception):
    """Base exception for the codec library."""
    pass

class CryptoError(CodecError):
    """Cryptographic operation failed."""
    pass

class KeyNotFoundError(CodecError):
    """Key not found in keystore."""
    pass

class SerializationError(CodecError):
    """Message serialization/deserialization failed."""
    pass

class VerificationError(CodecError):
    """Signature or MAC verification failed."""
    pass
