from typing import Optional
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from ..core.interfaces import CipherInterface
from ..core.models import StrBytes


class RSACipher(CipherInterface):
    """
    RSA-OAEP Asymmetric Encryption.

    Data compatibility: STRINGS ONLY, max length depends on key size.
    For 2048-bit key: max ~190 bytes (due to padding overhead).
    Use for key wrapping, not bulk data.
    """

    MAX_SIZE_2048 = 190  # bytes
    MAX_SIZE_4096 = 470  # bytes

    def __init__(self, private_key=None, public_key=None, key_size: int = 2048):
        """
        Initialize with existing keys or generate new pair.
        """
        self.key_size = key_size
        self.max_data_size = (
            self.MAX_SIZE_2048 if key_size == 2048 else self.MAX_SIZE_4096
        )

        if private_key:
            self.private_key = private_key
            self.public_key = private_key.public_key()
        elif public_key:
            self.private_key = None
            self.public_key = public_key
        else:
            self.private_key = rsa.generate_private_key(
                public_exponent=65537, key_size=key_size
            )
            self.public_key = self.private_key.public_key()

        self.cipher_name = f"RSA-OAEP-{key_size}"

    def is_data_compatible(self, data: StrBytes) -> bool:
        """
        RSA has strict limits:
        - String data only (we convert to bytes)
        - Maximum length: key_size/8 - 2*hash_len - 2 (for OAEP)
        """
        if not isinstance(data, (str, bytes)):
            return False

        data_len = len(data) if isinstance(data, str) else len(data)
        return data_len <= self.max_data_size

    def encrypt(self, data: str) -> str:
        """Encrypt with public key."""
        if not self.is_data_compatible(data):
            raise ValueError(
                f"RSA-{self.key_size} can only encrypt {self.max_data_size} bytes, "
                f"got {len(data)}"
            )

        if self.public_key is None:
            raise ValueError("No public key available for encryption")

        plaintext = data.encode("utf-8")
        ciphertext = self.public_key.encrypt(
            plaintext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        return self._b64encode(ciphertext)

    def decrypt(self, data: str) -> str:
        """Decrypt with private key."""
        if self.private_key is None:
            raise ValueError("No private key available for decryption")

        try:
            ciphertext = self._b64decode(data)
            plaintext = self.private_key.decrypt(
                ciphertext,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )
            return plaintext.decode("utf-8")
        except Exception as e:
            raise ValueError(f"RSA decryption failed: {e}")

    def export_public_key(self) -> str:
        """Export public key as PEM string."""
        pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return pem.decode("ascii")

    def export_private_key(self, password: Optional[str] = None) -> str:
        """Export private key as PEM (optionally encrypted)."""
        encryption = serialization.NoEncryption()
        if password:
            encryption = serialization.BestAvailableEncryption(password.encode())

        pem = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption,
        )
        return pem.decode("ascii")
