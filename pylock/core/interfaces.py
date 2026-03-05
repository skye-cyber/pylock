from pathlib import Path
from abc import ABC, abstractmethod
from typing import Protocol, Union
import base64
from ..config.model import ConfigModel
from .models import Ciphers, PyLockerAction

StrBytes = Union[str, bytes]


class PyLockInterface(ABC):
    """Suite interface"""

    @abstractmethod
    def save_keyfile(self, key, path: Path): ...

    @abstractmethod
    def write_file(self, path: Path, data: str, mode: str): ...

    @abstractmethod
    def read_file(self, path: Path): ...

    @abstractmethod
    def encrypt(self, data: str, key: str | bytes, cipher) -> str: ...

    @abstractmethod
    def decrypt(self, data: str, key: str | bytes, cipher) -> str: ...

    @abstractmethod
    def write_metadata(self, data: str | bytes): ...

    @abstractmethod
    def process_file(
        self,
        path: Path,
        passphrase: str,
        action: PyLockerAction,
        cipher: Ciphers = Ciphers.AES256GCMCipher,
        compress: bool = False,
        output_path: Path = None,
    ): ...

    @abstractmethod
    def process_dir(
        self,
        path: Path,
        passphrase: str,
        action: PyLockerAction,
        cipher: Ciphers = Ciphers.AES256GCMCipher,
        compress: bool = False,
        output_path: Path = None,
    ): ...

    @abstractmethod
    def read_encryption_info(self, path: Path) -> dict: ...

    @abstractmethod
    def is_encrypted(self, path: Path) -> bool: ...

    @abstractmethod
    def guess_cipher(self, info: dict): ...


class LockInterface(ABC):
    """Lock manager interface"""

    @abstractmethod
    def lock(self, path: Path, pid: int): ...
    @abstractmethod
    def unlock(self, path: Path, pid: int): ...
    @abstractmethod
    def is_locked(self, path: Path): ...
    @abstractmethod
    def get_lock_pid(self, path: Path): ...


class CipherInterface(ABC):
    """All ciphers must implement this interface."""

    @abstractmethod
    def encrypt(self, data: str) -> str:
        """Encrypt string data, return base64-encoded result."""
        pass

    @abstractmethod
    def decrypt(self, data: str) -> str:
        """Decrypt base64-encoded data, return original string."""
        pass

    @abstractmethod
    def is_data_compatible(self, data: StrBytes) -> bool:
        """Check if data type is compatible with this cipher."""
        pass

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
        enc = base64.urlsafe_b64decode(data.encode("ascii"))
        return enc


class Cipher(Protocol):
    def encrypt(self, data: str) -> str: ...
    def decrypt(self, data: str) -> str: ...
    def is_data_compartible(self, data: str | bytes) -> bool: ...


class KeyMnagerInterface(ABC):
    @staticmethod
    def random_enc_key() -> str: ...

    @staticmethod
    def derive_key_from_passphrase(
        passphrase: str, salt: bytes = ConfigModel.DEFAULTSALT
    ) -> tuple[bytes, bytes]: ...

    @staticmethod
    def key_to_hex(key: bytes) -> str: ...

    @staticmethod
    def hex_to_key(hex_str: str) -> bytes: ...
