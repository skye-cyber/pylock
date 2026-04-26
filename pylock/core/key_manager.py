import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from ..config.model import ConfigModel
from .interfaces import KeyMnagerInterface


class KeyManager(KeyMnagerInterface):
    """Handles key generation and derivation separately from ciphers."""

    @staticmethod
    def generate_random_key() -> bytes:
        """Generate a random 32-byte key."""
        return os.urandom(32)

    @staticmethod
    def derive_key_from_passphrase(
        passphrase: str, salt: bytes = ConfigModel.DEFAULTSALT
    ) -> tuple[bytes, bytes]:
        """
        Derive a 32-byte key from a passphrase.

        Returns:
            tuple: (key, salt) - salt needed for same derivation again
        """

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=480000,
            backend=default_backend(),
        )
        key = kdf.derive(passphrase.encode("utf-8"))
        # key = base64.urlsafe_b64encode(kdf.derive(passphrase.encode()))
        return key

    @staticmethod
    def key_to_hex(key: bytes) -> str:
        """Convert key to hex string for storage."""
        return key.hex()

    @staticmethod
    def hex_to_key(hex_str: str) -> bytes:
        """Convert hex string back to key bytes."""
        return bytes.fromhex(hex_str)
