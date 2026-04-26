from enum import Enum
import json
from typing import Union
from dataclasses import dataclass, asdict

StrBytes = Union[str, bytes]


class PyLockerAction(str, Enum):
    ENCRYPT = "encrypt"
    DECRYPT = "decrypt"


class Ciphers(str, Enum):
    AES256GCMCipher = "aes-256-gcm"
    ChaCha20Cipher = "chacha20"
    OneTimePadCipher = "otp"
    RSACipher = "rsa"
    Vigenere = "vigenere"
    HybridRSAAESCipher = "hybrid-rsa-aes"
    Fernet = "fernet"


LockerHeader: dict = {
    "version": str,
    "cipher": str,
    "timestamp": str,
}


@dataclass
class LockInfo:
    """Metadata stored in lock files."""

    pid: int
    created_at: float
    operation: str  # 'encrypt', 'decrypt', 'process', etc.
    target_path: str

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2)

    @classmethod
    def from_json(cls, data: str) -> "LockInfo":
        return cls(**json.loads(data))
