from enum import Enum


class PyLockerAction(str, Enum):
    ENCRYPT = "encrypt"
    DECRYPT = "decrypt"


LockerHeader: dict = {
    "version": str,
    "cipher": str,
    "timestamp": str,
}
