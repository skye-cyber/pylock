"""
Implementation of the core cnryption logic
"""

import base64
from pathlib import Path
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from .exceptions import SuiteError, KeyError
from .interfaces import SuiteInterface
from ..config.model import ConfigModel


class BaseEncryptor(SuiteInterface):
    @property
    def random_enc_key() -> str:
        """
        Generate Random encryption key
        """
        try:
            return Fernet.generate_key().decode()
        except Exception as e:
            raise SuiteError(e)

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
            return key
        except Exception as e:
            raise SuiteError(e)

    def save_keyfile(self, key, path: Path):
        """
        DEPRECATED In favour of f user storing the key
        """
        try:
            if path.exists():
                raise SuiteError("KeyFile is already in use")

            key_string = key.decode()
            keyfile = path.stem + ".xml"

            with open(keyfile, "x") as file:
                file.write(key_string)
        except Exception as e:
            raise SuiteError(e)

    def write_file(self, path: Path, data: str, mode: str = "wb"):
        """
        TODO Modify the data before saving to append encryption infor
        This shall be used inplace of using file extensions to denote encryption status
        """
        if path.exists():
            raise SuiteError(f"File Exists at {path}")

        with open(path, mode) as file:
            file.write()
        return self

    def read_file(self, path: Path):
        if path.exists():
            raise SuiteError(f"File Not Found at {path}")

        with open(path, "rb") as file:
            data = file.read()
        return data

    def encrypt(self, data: str | bytes, key: str | bytes, cipher=Fernet) -> str:
        if not key:
            raise KeyError("Encryption key missing")

        key = key.encode() if isinstance(key, str) else key

        cipher = cipher(key)

        self.save_keyfile(key)

        encrypted_data = cipher.encrypt(data)

        return encrypted_data

    def decrypt(self, data: str | bytes, key: str | bytes, cipher=Fernet) -> str:
        if not key:
            raise KeyError("Missing decryption key")

        key = key.encode() if isinstance(key, str) else key

        cipher = cipher(key)

        decrypted_data = cipher.decrypt(data)

        return decrypted_data
