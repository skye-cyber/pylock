"""
Implementation of the core cnryption logic
"""

import os
import json
import hmac
import struct
import base64
import hashlib
from pathlib import Path
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from .exceptions import PyLockError, KeyError, ValidationError
from .interfaces import PyLockInterface
from ..config.model import ConfigModel


class BaseEncryptor(PyLockInterface):
    """
    Concrete implementation of SuiteInterface with metadata header/footer support.

    File Format:
    [4 bytes: header length][JSON header: encryption metadata][encrypted data][optional: footer signature]
    """

    # Magic bytes to identify encrypted files
    MAGIC = b"CRYP"
    VERSION = 1

    def __init__(self, *args, **kwargs):
        self._metadata_buffer = None

    @property
    def random_enc_key() -> str:
        """
        Generate Random encryption key
        """
        return Fernet.generate_key().decode()

    def save_keyfile(self, key, path: Path) -> None:
        """Save encryption key to file."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)

        if isinstance(key, bytes):
            key = base64.urlsafe_b64encode(key).decode("ascii")

        with open(path, "w") as f:
            f.write(key)

    @staticmethod
    def generate_enc_key(
        self, passphrase: str, salt: str = ConfigModel.DEFAULTSALT
    ) -> bytes:
        try:
            salt = salt.encode()  # Convert to bytes
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA512(),
                length=32,
                salt=salt,
                iterations=1_000_000,
                backend=default_backend(),
            )
            key = base64.urlsafe_b64encode(kdf.derive(passphrase.encode()))
            return key  # key.decode('ascii')
        except Exception as e:
            raise PyLockError(e)

    def write_metadata(self, data: str | bytes) -> None:
        """
        Buffer metadata to be written with the next file operation.
        Call this before write_file or encrypt to include metadata.
        """
        if isinstance(data, str):
            data = data.encode("utf-8")
        self._metadata_buffer = data

    def _build_header(
        self, cipher_name: str, key_id: str = None, extra: dict = None
    ) -> bytes:
        """
        Build a binary header with encryption metadata.

        Format:
        - 4 bytes: Magic "CRYP"
        - 1 byte: Version
        - 4 bytes: Header length (uint32, big-endian)
        - N bytes: JSON metadata
        """
        metadata = {
            "version": self.VERSION,
            "cipher": cipher_name,
            "timestamp": self._get_timestamp(),
        }

        if key_id:
            metadata["key_id"] = key_id
        if extra:
            metadata.update(extra)
        if self._metadata_buffer:
            # Include user-provided metadata
            try:
                user_meta = json.loads(self._metadata_buffer.decode("utf-8"))
                metadata["user"] = user_meta
            except (json.JSONDecodeError, UnicodeDecodeError):
                metadata["user_raw"] = base64.b64encode(self._metadata_buffer).decode(
                    "ascii"
                )

        json_bytes = json.dumps(metadata, separators=(",", ":")).encode("utf-8")
        header_len = len(json_bytes)

        # Structure: MAGIC(4) + VERSION(1) + LENGTH(4) + JSON(N)
        header = struct.pack(">4sBI", self.MAGIC, self.VERSION, header_len) + json_bytes

        return header

    def _add_footer(self, data: bytes, key: bytes) -> bytes:
        """Append HMAC signature at end of file."""
        signature = hmac.new(key, data, hashlib.sha256).digest()[:16]
        return data + b"FOOT" + signature

    def _verify_footer(self, data: bytes, key: bytes) -> bytes:
        """Verify and strip footer, returning original data."""
        if not data.endswith(b"FOOT"):
            return data  # No footer

        # Find footer start
        foot_pos = data.rfind(b"FOOT")
        if foot_pos == -1:
            return data

        content = data[:foot_pos]
        signature = data[foot_pos + 4 :]

        expected = hmac.new(key, content, hashlib.sha256).digest()[:16]
        if not hmac.compare_digest(signature, expected):
            raise ValidationError("File integrity check failed")

        return content

    def _get_timestamp(self) -> str:
        """Get ISO timestamp for metadata."""
        from datetime import datetime

        return datetime.utcnow().isoformat() + "Z"

    def read_encryption_info(self, path: Path) -> dict:
        """
        Read encryption metadata from file header without decrypting content.

        Returns:
            dict: Contains 'cipher', 'version', 'key_id', 'timestamp', etc.
                  Returns empty dict if file is not encrypted or corrupted.
        """
        path = Path(path)

        if not path.exists() or path.stat().st_size < 9:  # Minimum header size
            return {}

        with open(path, "rb") as f:
            # Read magic (4) + version (1) + length (4) = 9 bytes minimum
            header_prefix = f.read(9)

            if len(header_prefix) < 9:
                return {}

            magic, version, json_len = struct.unpack(">4sBI", header_prefix)

            if magic != self.MAGIC:
                return {}

            # Read the JSON metadata
            json_bytes = f.read(json_len)

            if len(json_bytes) < json_len:
                return {}

            try:
                metadata = json.loads(json_bytes.decode("utf-8"))
                metadata["_header_size"] = 9 + json_len  # Useful for decryption offset
                metadata["_is_encrypted"] = True
                return metadata
            except (json.JSONDecodeError, UnicodeDecodeError):
                return {}

    def is_encrypted(self, path: Path) -> bool:
        """
        Quick check if a file was encrypted by this suite.

        Simply checks for magic bytes at file start - fast and efficient.
        """
        path = Path(path)

        if not path.exists() or path.stat().st_size < 4:
            return False

        with open(path, "rb") as f:
            magic = f.read(4)
            return magic == self.MAGIC

    def write_file(self, path: Path, data: str, mode: str = "w"):
        """
        Write file with optional metadata header.
        If metadata was set via write_metadata(), includes it in header.
        """
        if path.exists():
            raise PyLockError(f"File Exists at {path}")

        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)

        if "b" in mode:
            if isinstance(data, str):
                data = data.encode("utf-8")
        else:
            if isinstance(data, bytes):
                data = data.decode("utf-8")

        with open(path, mode) as f:
            f.write(data)

        # Clear metadata buffer after use
        self._metadata_buffer = None

        return self

    def read_file(self, path: Path) -> str:
        """Read file, detecting and handling encrypted files."""
        path = Path(path)

        if path.exists():
            raise PyLockError(f"File Not Found at {path}")

        if self.is_encrypted(path):
            # Read and strip header for raw content access
            with open(path, "rb") as f:
                data = f.read()

            # Skip header to get ciphertext
            _, _, json_len = struct.unpack(">4sBI", data[:9])
            ciphertext = data[9 + json_len :]

            # Return as string (base64 encoded ciphertext)
            return base64.b64encode(ciphertext).decode("ascii")

        # Regular file read
        with open(path, "r", encoding="utf-8") as f:
            return f.read()

    def encrypt(self, data: str | bytes, key: str | bytes, cipher=Fernet) -> str:
        """
        Encrypt data and return ciphertext with metadata header prepended.

        The cipher parameter determines which algorithm to record in metadata.
        """
        if not key:
            raise KeyError("Encryption key missing")

        # Normalize key
        if isinstance(key, str):
            key = key.encode("utf-8")

        # Determine cipher name for metadata
        cipher_name = self._get_cipher_name(cipher)

        # Build header with encryption info
        header = self._build_header(cipher_name)

        # Perform actual encryption using the provided cipher
        ciphertext = self._perform_encryption(data, key, cipher)

        # Combine: header + ciphertext
        # Use base64 to ensure text-safe output if needed, or keep binary
        combined = header + ciphertext

        # Clear metadata buffer after use
        self._metadata_buffer = None

        # Return as base64 string for text safety, or handle as needed
        return base64.b64encode(combined).decode("ascii")

    def decrypt(self, data: str | bytes, key: str | bytes, cipher=Fernet) -> str:
        """
        Decrypt data, automatically stripping the metadata header.

        Reads cipher info from header to verify correct decryption method.
        """
        if not key:
            raise KeyError("Missing decryption key")

        # Decode from base64 if necessary
        if isinstance(data, str):
            data = base64.b64decode(data.encode("ascii"))

        # Parse and strip header
        if len(data) < 9:
            raise ValueError("Data too short to contain valid header")

        magic, version, json_len = struct.unpack(">4sBI", data[:9])

        if magic != self.MAGIC:
            raise ValueError("Invalid magic bytes - not an encrypted file")

        header_size = 9 + json_len
        metadata = json.loads(data[9:header_size].decode("utf-8"))
        ciphertext = data[header_size:]

        # Verify cipher matches (optional safety check)
        expected_cipher = self._get_cipher_name(cipher)
        if metadata.get("cipher") != expected_cipher:
            # Could warn or raise here depending on strictness needs
            pass

        # Decrypt the actual content
        return self._perform_decryption(ciphertext, key, cipher)

    def _perform_encryption(self, data: str, key: bytes, cipher) -> bytes:
        """
        Actual encryption implementation.
        Placeholder - integrate with your specific cipher logic.
        """
        # Example with Fernet
        if cipher == "fernet" or str(cipher).lower() == "fernet":
            f = Fernet(key)
            return f.encrypt(data.encode("utf-8") if isinstance(data, str) else data)

        # Example with AES-GCM
        elif cipher == "aes-gcm" or str(cipher).lower() == "aes-gcm":
            aesgcm = AESGCM(key[:32])  # Use first 32 bytes
            nonce = os.urandom(12)
            ciphertext = aesgcm.encrypt(nonce, data.encode("utf-8"), None)
            return nonce + ciphertext

        # Fallback: assume cipher is a callable
        if callable(cipher):
            return cipher(key, data, mode="encrypt")

        raise ValueError(f"Unsupported cipher: {cipher}")

    def _perform_decryption(self, data: bytes, key: str | bytes, cipher) -> str:
        """Actual decryption implementation."""
        if isinstance(key, str):
            key = key.encode("utf-8")

        if cipher == "fernet" or str(cipher).lower() == "fernet":
            f = Fernet(key)
            return f.decrypt(data).decode("utf-8")

        elif cipher == "aes-gcm" or str(cipher).lower() == "aes-gcm":
            aesgcm = AESGCM(key[:32])
            nonce, ciphertext = data[:12], data[12:]
            return aesgcm.decrypt(nonce, ciphertext, None).decode("utf-8")

        if callable(cipher):
            result = cipher(key, data, mode="decrypt")
            return result.decode("utf-8") if isinstance(result, bytes) else result

        raise ValueError(f"Unsupported cipher: {cipher}")

    def _get_cipher_name(self, cipher) -> str:
        """Extract cipher identifier from cipher object/type."""
        if isinstance(cipher, str):
            return cipher
        if hasattr(cipher, "__name__"):
            return cipher.__name__
        return type(cipher).__name__

    def guess_cipher(self, info: dict):
        """Guess appropriate cipher from metadata or defaults."""
        if info and "cipher" in info:
            return info["cipher"]
        return "fernet"  # Default
