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
