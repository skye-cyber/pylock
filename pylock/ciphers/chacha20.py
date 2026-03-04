import os
from typing import Optional
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from ..core.interfaces import CipherInterface
from ..core.models import StrBytes


class ChaCha20Cipher(CipherInterface):
    """
    ChaCha20-Poly1305 AEAD Stream Cipher.

    Data compatibility: Accepts str only, but optimized for binary data workflows.
    Faster than AES on software implementations, no hardware required.
    """

    def __init__(self, key: Optional[bytes] = None):
        """Key must be 32 bytes."""
        self.key = key if key and len(key) == 32 else os.urandom(32)
        self.cipher_name = "ChaCha20-Poly1305"

    def is_data_compatible(self, data: StrBytes) -> bool:
        """ChaCha20 accepts any string data."""
        return isinstance(data, (str, bytes))

    def encrypt(self, data: str) -> str:
        """Encrypt with ChaCha20-Poly1305."""
        if not isinstance(data, str):
            raise TypeError(f"ChaCha20 expects str, got {type(data).__name__}")

        chacha = ChaCha20Poly1305(self.key)
        nonce = os.urandom(12)
        plaintext = data.encode("utf-8")
        ciphertext = chacha.encrypt(nonce, plaintext, None)

        return self._b64encode(nonce + ciphertext)

    def decrypt(self, data: str) -> str:
        """Decrypt ChaCha20 ciphertext."""
        try:
            combined = self._b64decode(data)
            nonce, ciphertext = combined[:12], combined[12:]

            chacha = ChaCha20Poly1305(self.key)
            plaintext = chacha.decrypt(nonce, ciphertext, None)
            return plaintext.decode("utf-8")
        except Exception as e:
            raise ValueError(f"Decryption failed: {e}")
