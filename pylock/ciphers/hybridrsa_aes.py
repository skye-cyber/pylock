import os
from typing import Optional
from ..core.interfaces import CipherInterface
from .rsa import RSACipher
from .ase256gsm import AES256GCMCipher
from ..core.models import StrBytes


class HybridRSAAESCipher(CipherInterface):
    """
    Hybrid encryption: RSA encrypts AES key, AES encrypts data.

    Data compatibility: Any string length (RSA limitation bypassed via AES).
    Combines RSA (key exchange) + AES-256-GCM (bulk encryption).
    """

    def __init__(self, rsa_cipher: Optional[RSACipher] = None):
        self.rsa = rsa_cipher or RSACipher(key_size=2048)
        self.cipher_name = "Hybrid-RSA-AES"

    def is_data_compatible(self, data: StrBytes) -> bool:
        """Hybrid accepts any string (AES handles bulk, RSA handles key)."""
        return isinstance(data, str)

    def encrypt(self, data: str) -> str:
        """Generate random AES key, encrypt data with AES, encrypt key with RSA."""
        # Generate ephemeral AES key
        aes_key = os.urandom(32)
        aes = AES256GCMCipher(key=aes_key)

        # Encrypt data with AES
        encrypted_data = aes.encrypt(data)

        # Encrypt AES key with RSA
        encrypted_key = self.rsa.encrypt(self._b64encode(aes_key))

        # Format: encrypted_key | encrypted_data
        combined = f"{encrypted_key}:{encrypted_data}"
        return self._b64encode(combined.encode("utf-8"))

    def decrypt(self, data: str) -> str:
        """Decrypt AES key with RSA, then decrypt data with AES."""
        try:
            combined = self._b64decode(data).decode("utf-8")
            encrypted_key, encrypted_data = combined.split(":", 1)

            # Decrypt AES key
            aes_key_b64 = self.rsa.decrypt(encrypted_key)
            aes_key = self._b64decode(aes_key_b64)

            # Decrypt data
            aes = AES256GCMCipher(key=aes_key)
            return aes.decrypt(encrypted_data)
        except Exception as e:
            raise ValueError(f"Hybrid decryption failed: {e}")
