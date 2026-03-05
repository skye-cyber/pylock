"""
Implementation of the core cnryption logic
"""

import json
import hmac
import struct
import base64
import hashlib
from pathlib import Path
from .exceptions import PyLockError, KeyError, ValidationError
from .interfaces import PyLockInterface, CipherInterface
from .models import Ciphers
from ..ciphers.factory import CipherFactory
from .key_manager import KeyManager


class BaseEncryptor(PyLockInterface, KeyManager):
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

    def save_keyfile(self, key, path: Path) -> None:
        """Save encryption key to file."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)

        if isinstance(key, bytes):
            key = base64.urlsafe_b64encode(key).decode("ascii")

        with open(path, "w") as f:
            f.write(key)

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

        # Build binary header
        header = (
            struct.pack(">4sBI", self.MAGIC, self.VERSION, len(json_bytes)) + json_bytes
        )

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

        if (
            not path.exists() or path.stat().st_size < 12
        ):  # Minimum size for Base64 header
            return {}

        with open(path, "rb") as f:
            # Read enough for potential Base64 header (could be larger than binary header)
            # Since Base64 expands data by ~33%, we need to read more
            # Let's read up to 1024 bytes to ensure we capture the full header
            raw_data = f.read(1024)

            try:
                # Decode the Base64 data
                decoded_data = base64.b64decode(raw_data)
            except base64.binascii.Error:
                # Not valid Base64 - might be unencrypted file or corrupted
                return {}

            # Check if we have enough data for header
            if (
                len(decoded_data) < 9
            ):  # Minimum header size (magic 4 + version 1 + length 4)
                return {}

            # Extract binary header
            magic, version, json_len = struct.unpack(">4sBI", decoded_data[:9])

            if magic != self.MAGIC:
                return {}

            # Ensure we have the full JSON data
            if len(decoded_data) < 9 + json_len:
                # Try to read more if needed
                f.seek(len(raw_data))
                additional_data = f.read(json_len - (len(decoded_data) - 9))
                if additional_data:
                    try:
                        decoded_more = base64.b64decode(additional_data)
                        decoded_data += decoded_more
                    except base64.binascii.Error:
                        return {}

            if len(decoded_data) < 9 + json_len:
                return {}

            # Extract JSON data
            json_bytes = decoded_data[9 : 9 + json_len]

            try:
                metadata = json.loads(json_bytes.decode("utf-8"))
                # Calculate header size including Base64 encoding overhead
                original_header_size = 9 + json_len
                metadata["_header_size"] = len(
                    base64.b64encode(decoded_data[:original_header_size])
                )
                metadata["_is_encrypted"] = True
                return metadata
            except (json.JSONDecodeError, UnicodeDecodeError):
                return {}

    def is_encrypted(self, path: Path) -> bool:
        """
        Quick check if a file was encrypted by this suite.

        Handles both raw binary and Base64-encoded formats.
        """
        path = Path(path)

        if not path.exists() or path.stat().st_size < 8:  # Minimum for Base64 header
            return False

        with open(path, "rb") as f:
            # Read enough to potentially contain the magic bytes after Base64 decode
            # Base64 of 4 bytes is 8 characters, plus some buffer
            raw_data = f.read(8)  # Read a reasonable chunk

            try:
                # Try to decode as Base64 first (since your format encodes everything)
                decoded = base64.b64decode(raw_data)

                # Check if decoded data starts with magic bytes
                if len(decoded) >= 4 and decoded[:4] == self.MAGIC:
                    return True

            except base64.binascii.Error:
                # Not valid Base64 - might be raw binary or unencrypted
                pass

            # If Base64 decode failed, check if raw data starts with magic
            # (for backward compatibility or raw binary format)
            if len(raw_data) >= 4 and raw_data[:4] == self.MAGIC:
                return True

        return False

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
            f.write(data)  # f.write(base64.b64decode(ciphertext))

        # Clear metadata buffer after use
        self._metadata_buffer = None

        return self

    def read_file(self, path: Path) -> str:
        """Read file, detecting and handling encrypted files."""
        path = Path(path)

        if not path.exists():
            raise PyLockError(f"File Not Found at {path}")

        # if self.is_encrypted(path):
        #     # Read and strip header for raw content access
        #     with open(path, "r") as f:
        #         data = f.read()
        #
        #     # Skip header to get ciphertext
        #     _, _, json_len = struct.unpack(">4sBI", data[:9])
        #     ciphertext = data[9 + json_len :]
        #
        #     # Return as string (base64 encoded ciphertext)
        #     return base64.b64encode(ciphertext).decode("ascii")

        # Regular file read
        with open(path, "r", encoding="utf-8") as f:
            return f.read()

    def encrypt(
        self,
        data: str | bytes,
        key: str | bytes,
        cipher: CipherInterface = Ciphers.AES256GCMCipher,
    ) -> str:
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

    def decrypt(
        self,
        data: str | bytes,
        key: str | bytes,
        info,
        cipher: CipherInterface = Ciphers.AES256GCMCipher,
    ) -> str:
        """
        Decrypt data, automatically stripping the metadata header.

        Reads cipher info from header to verify correct decryption method.
        """
        if not key:
            raise KeyError("Missing decryption key")

        # STEP 1: Convert input to binary data
        if isinstance(data, str):
            # Data is a Base64 string (header + nonce + ciphertext)
            binary_data = base64.b64decode(data.encode("ascii"))
        else:
            # Data is bytes - might be Base64 or raw
            try:
                binary_data = base64.b64decode(data)
            except base64.binascii.Error:
                binary_data = data

        # STEP 2: Extract header and ciphertext (which includes nonce)
        binary_header_size = info.get("_header_size", 0)

        if binary_header_size == 0 or len(binary_data) < binary_header_size:
            raise PyLockError(f"Invalid header size: {binary_header_size}")

        # This contains: nonce(12) + actual ciphertext
        ciphertext_with_nonce = binary_data[binary_header_size:]

        print(f"Header size: {binary_header_size}")
        print(f"Total binary data: {len(binary_data)}")
        print(f"Ciphertext with nonce: {len(ciphertext_with_nonce)} bytes")
        print(
            f"Nonce should be first 12 bytes, then {len(ciphertext_with_nonce) - 12} bytes ciphertext"
        )

        # STEP 3: Get the correct cipher from metadata if specified
        expected_cipher_name = info.get("cipher")
        if expected_cipher_name:
            expected_cipher = CipherFactory.CIPHERS.get(expected_cipher_name)
            if expected_cipher and cipher != expected_cipher:
                cipher = expected_cipher
                print(f"Using cipher from metadata: {expected_cipher_name}")

        # STEP 4: Decrypt - pass the bytes with nonce+ciphertext
        try:
            decrypted_data = self._perform_decryption(
                ciphertext_with_nonce, key, cipher
            )
        except Exception as e:
            raise PyLockError(e.__str__())

        if not decrypted_data:
            raise PyLockError("Could not decrypt data: Invalid key")

        print(f"Decrypted data length: {len(decrypted_data)} characters")
        return decrypted_data

    def _perform_encryption(
        self, data: str | bytes, key: bytes, cipher: Ciphers.AES256GCMCipher
    ) -> bytes:
        """
        Actual encryption implementation.

        Args:
            data: Data to encrypt (str or bytes)
            key: Encryption key as bytes
            cipher_class: Cipher class to instantiate

        Returns:
            Raw bytes containing (nonce + ciphertext + tag)
        """
        if not cipher or not callable(cipher):
            raise ValidationError(f"Unsupported cipher: {cipher}")

        # Create cipher instance with the key
        f = cipher(key=key)

        # Encrypt - cipher.encrypt() returns Base64 string (per interface)
        encrypted_b64 = f.encrypt(data)

        # Convert Base64 to raw bytes for combining with header
        return f._b64decode(encrypted_b64)

    def _perform_decryption(
        self, data: bytes, key: str | bytes, cipher: Ciphers.AES256GCMCipher
    ) -> str:
        """
        Actual decryption implementation.

        Args:
            data: Raw bytes containing (nonce + ciphertext + tag)
            key: Decryption key as bytes
            cipher_class: Cipher class to instantiate

        Returns:
            Decrypted string
        """
        # Normalize key to bytes
        if isinstance(key, str):
            key = key.encode("utf-8")

        if not cipher or not callable(cipher):
            raise ValidationError(f"Unsupported cipher: {cipher}")

        # Create cipher instance
        f = cipher(key)

        # The cipher's decrypt method expects either:
        # - Base64 string, or
        # - Bytes containing (nonce + ciphertext)
        # And returns a decoded string

        # Since we already have bytes with nonce+ciphertext,
        # we can pass it directly
        # decrypted = f.decrypt(data)  # data is bytes with nonce + ciphertext

        # Convert raw bytes to Base64 string (what cipher.decrypt expects)
        data_b64 = f._b64encode(data)

        # Decrypt - cipher.decrypt() returns string directly
        return f.decrypt(data_b64)

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
        return "aes-256-gcm"  # Default

    def get_cipher_byname(self, name: str) -> CipherInterface:
        return CipherFactory.CIPHERS.get(name, None)
