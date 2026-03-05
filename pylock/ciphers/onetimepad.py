from typing import Optional
from ..core.interfaces import CipherInterface
from ..core.models import StrBytes
from ..core.exceptions import ValidationError


class OneTimePadCipher(CipherInterface):
    """
    One-Time Pad - information-theoretically secure IF used correctly.

    Data compatibility: STR ONLY, but length restricted.
    Key must be as long as message, used exactly once, truly random.
    """

    def __init__(self, key: Optional[bytes] = None):
        self.key = key
        self.used = False  # Track if key has been used (safety)
        self.cipher_name = "One-Time-Pad"

    def is_data_compatible(self, data: StrBytes) -> bool:
        """
        OTP requires:
        1. String data only
        2. Key must be pre-shared and same length as data
        3. Key must not be reused (enforced here)
        """
        if not isinstance(data, (str, bytes)):
            return False

        data_len = len(data)  # if isinstance(data, str) else len(data)

        if self.key is None:
            return False  # No key provided
        if len(self.key) < data_len:
            return False  # Key too short
        if self.used:
            return False  # Already used (security violation)

        return True

    def encrypt(self, data: StrBytes) -> str:
        """XOR data with key. DESTROYS key after use."""
        if not self.is_data_compatible(data):
            raise ValidationError(
                "OTP incompatible: ensure key length >= data length and unused"
            )

        plaintext = data.encode("utf-8") if isinstance(data, str) else data
        # XOR each byte
        ciphertext = bytes(p ^ k for p, k in zip(plaintext, self.key))

        self.used = True  # Mark as used
        return self._b64encode(ciphertext)

    def decrypt(self, data: StrBytes) -> str:
        """XOR is symmetric: ciphertext ^ key = plaintext."""
        if not self.used:
            raise ValidationError("OTP key not marked as used - possible key reuse")

        ciphertext = self._b64decode(data)
        # XOR again to decrypt
        plaintext = bytes(c ^ k for c, k in zip(ciphertext, self.key))

        return plaintext.decode("utf-8")
