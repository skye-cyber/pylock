from enum import Enum
import json
from typing import Protocol, Type, Callable, Any
from dataclasses import dataclass, asdict
from ..ciphers.caesar import Caesar
from ..ciphers.playfair import Playfair
from ..ciphers.vigenere import Vigenere
from .interfaces import CipherInterface


class PyLockerAction(str, Enum):
    ENCRYPT = "encrypt"
    DECRYPT = "decrypt"


CIPHERS: dict[str, Type[CipherInterface]] = {}

Ciphers = {
    "caesar": Caesar,
    "vigenere": Playfair,
    "playfair": Vigenere,
}

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
