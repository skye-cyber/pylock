import os
import base64
from typing import Optional
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from ..core.interfaces import CipherInterface
from ..core.models import StrBytes
from ..core.exceptions import ValidationError


class AES256GCMCipher(CipherInterface):
    """
    AES-256-GCM Authenticated Encryption.

    Pure cipher implementation - only encrypts/decrypts with provided key.
    Key must be exactly 32 bytes (256 bits).
    """

    def __init__(self, key: Optional[bytes] = None):
        """
        Initialize with a pre-derived 32-byte key.

        Args:
            key: Exactly 32 bytes (256 bits)

        Raises:
            ValidationError: If key is not 32 bytes
        """

        self.key = key
        self.cipher_name = "AES-256-GCM"

    def validate_key(self):
        if not isinstance(self.key, bytes):
            raise ValidationError(f"Key must be bytes, got {type(self.key).__name__}")

        if len(self.key) != 32:
            raise ValidationError(f"Key must be 32 bytes, got {len(self.key)}")

    def is_data_compatible(self, data: StrBytes) -> bool:
        """AES-GCM accepts any string data."""
        return isinstance(data, (str, bytes))

    def encrypt(self, data: StrBytes) -> str:
        """
        Encrypt data.

        Returns: Base64-encoded (nonce + ciphertext + tag)
        """
        self.validate_key()
        # Convert string to bytes if needed
        plaintext = data.encode("utf-8") if isinstance(data, str) else data

        # Generate random nonce (12 bytes for GCM)
        nonce = os.urandom(12)

        # Encrypt
        aesgcm = AESGCM(self.key)
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)

        # Combine nonce + ciphertext (which includes tag)
        combined = nonce + ciphertext

        # Return as Base64 string
        return base64.b64encode(combined).decode("ascii")

    def decrypt(self, data: StrBytes) -> str:
        """
        Decrypt data.

        Args:
            data: Either:
                - Base64-encoded string (nonce + ciphertext + tag), or
                - Raw bytes (nonce + ciphertext + tag)

        Returns: Decrypted string
        """
        self.validate_key()

        # Use the interface helper to decode from Base64 if it's a string
        # _b64decode handles both str and bytes input consistently
        if isinstance(data, str):
            combined = self._b64decode(data)  # String → decode → bytes
        else:
            # If it's bytes, assume it's already raw bytes (not Base64)
            # But check if it might be Base64-encoded bytes
            try:
                # Try to decode as Base64 (in case it's Base64 bytes)
                combined = self._b64decode(
                    data.decode("ascii") if isinstance(data, bytes) else data
                )
            except (base64.binascii.Error, UnicodeDecodeError):
                # Not Base64, treat as raw bytes
                combined = data

        # Extract nonce and ciphertext
        if len(combined) < 12:
            raise ValidationError(
                f"Data too short: expected at least 12 bytes for nonce, got {len(combined)}"
            )

        nonce, ciphertext = combined[:12], combined[12:]

        # Decrypt
        try:
            aesgcm = AESGCM(self.key)
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        except Exception as e:
            raise ValidationError(f"Invalid key {e}")

        # Return as string using interface helper
        return self._to_str(plaintext)
