import base64
from typing import Optional
from cryptography.fernet import Fernet as fnt
from ..core.models import StrBytes
# from ..core.exceptions import ValidationError, PyLockError


class Fernet(fnt):
    """
    Fernet encryption
    Wrap around fernet module
    """

    def __init__(self, key: Optional[bytes] = None, *args, **kwargs):
        self.key = base64.urlsafe_b64encode(key) if key else None
        if self.key:
            super().__init__(key=self.key, *args, **kwargs)

    def is_data_compatible(self, data: StrBytes) -> bool:
        """AES-GCM accepts any string data."""
        return isinstance(data, (str, bytes))

    def _to_bytes(self, data: StrBytes) -> bytes:
        """Helper: convert str/bytes to bytes."""
        if isinstance(data, str):
            return data.encode("utf-8")
        return data

    def _to_str(self, data: bytes) -> str:
        """Helper: convert bytes to string."""
        return data.decode("utf-8")

    def _b64encode(self, data: bytes) -> str:
        """Helper: base64 encode to URL-safe string."""
        return base64.urlsafe_b64encode(data).decode("ascii")

    def _b64decode(self, data: str) -> bytes:
        """Helper: base64 decode from string."""
        return base64.urlsafe_b64decode(data.encode("ascii"))

    def encrypt(self, data: StrBytes) -> str:
        """Encrypt data using Fernet."""
        if not self.key:
            raise ValueError("Fernet key not set")
        
        # Convert data to bytes
        data_bytes = self._to_bytes(data)
        
        # Encrypt using parent class method
        encrypted_bytes = super().encrypt(data_bytes)
        
        # Return as base64 string
        return self._b64encode(encrypted_bytes)

    def decrypt(self, data: StrBytes) -> str:
        """Decrypt data using Fernet."""
        if not self.key:
            raise ValueError("Fernet key not set")
        
        # Convert data to bytes if it's a string
        if isinstance(data, str):
            data_bytes = self._b64decode(data)
        else:
            data_bytes = data
        
        # Decrypt using parent class method
        decrypted_bytes = super().decrypt(data_bytes)
        
        # Return as string
        return self._to_str(decrypted_bytes)
