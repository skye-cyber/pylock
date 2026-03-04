import os
from typing import Optional
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from ..core.interfaces import CipherInterface
from ..core.models import StrBytes


class AES256GCMCipher(CipherInterface):
    """
    AES-256-GCM Authenticated Encryption.

    Data compatibility: Accepts str only (converts to bytes internally).
    Returns base64(nonce + ciphertext + tag).
    """

    def __init__(self, key: Optional[bytes] = None, password: Optional[str] = None):
        """
        Initialize with key or derive from password.
        Key must be 32 bytes (256 bits).
        """
        if key and len(key) == 32:
            self.key = key
        elif password:
            self.key = self._derive_key(password)
        else:
            self.key = os.urandom(32)

        self.cipher_name = "AES-256-GCM"

    def _derive_key(self, password: str, salt: Optional[bytes] = None) -> bytes:
        """Derive 256-bit key from password using PBKDF2."""
        if salt is None:
            salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=480000,
        )
        key = kdf.derive(password.encode("utf-8"))
        # Return salt + key for storage (in real use, store salt separately)
        return salt + key

    def is_data_compatible(self, data: StrBytes) -> bool:
        """AES-GCM accepts any string data."""
        return isinstance(data, (str, bytes))

    def encrypt(self, data: str) -> str:
        """Encrypt: base64(salt + nonce + ciphertext + tag)."""
        if not isinstance(data, str):
            raise TypeError(f"AES-GCM expects str, got {type(data).__name__}")

        aesgcm = AESGCM(self.key)
        nonce = os.urandom(12)  # 96-bit IV
        plaintext = data.encode("utf-8")
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)

        # ciphertext includes auth tag (last 16 bytes)
        combined = nonce + ciphertext
        return self._b64encode(combined)

    def decrypt(self, data: str) -> str:
        """Decrypt and verify authentication tag."""
        try:
            combined = self._b64decode(data)
            nonce, ciphertext = combined[:12], combined[12:]

            aesgcm = AESGCM(self.key)
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
            return plaintext.decode("utf-8")
        except Exception as e:
            raise ValueError(f"Decryption failed: {e}")
