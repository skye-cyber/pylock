from enum import Enum


class SuiteAction(str, Enum):
    ENCRYPT = "encrypt"
    DECRYPT = "decrypt"
