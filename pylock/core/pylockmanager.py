"""Core encryption Logic: Integrated"""

import json
from pathlib import Path
from .pylock import BaseEncryptor
from .models import PyLockerAction
from ..utils.file_utils import FileSystemHandler
from ..utils.decorators import decorators
from .exceptions import UserError, ValidationError, SystemError
from .models import Ciphers
from ..ciphers.factory import CipherFactory


class PyLock(BaseEncryptor):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.fs = FileSystemHandler()
        self.processed_items = 0

    def process_file(
        self,
        path: Path,
        passphrase: str,
        action: PyLockerAction,
        cipher: Ciphers = Ciphers.AES256GCMCipher,
        compress: bool = False,
        output_path: Path = None,
    ):
        """Encrypt a single file in-place with metadata header."""
        path = path.expanduser().absolute()
        output_path = output_path.expanduser().absolute() if output_path else path

        if not path.exists():
            raise SystemError(f"File Not Found at {path}")

        if path.is_dir() and passphrase:
            self.process_dir(path, passphrase, cipher, action, compress, output_path)

        data = self.read_file(path)

        # Set up metadata if needed
        self.write_metadata(
            json.dumps(
                {"original_name": path.name, "original_size": path.stat().st_size}
            )
        )
        key = self.derive_key_from_passphrase(passphrase)

        if action == PyLockerAction.ENCRYPT:
            if self.is_encrypted(path):
                raise ValidationError("File is already encrypted")

            output_path = self.get_enc_output_file(output_path)
            # Determine cipher from configuration
            cipher_class = CipherFactory.CIPHERS.get(cipher, None)
            cipher = cipher_class
            _data = self.encrypt(data, key, cipher)

        elif action == PyLockerAction.DECRYPT:
            info = self.read_encryption_info(path)
            if not self.is_encrypted(path):
                raise ValidationError("File is not encrypted")

            output_path = self.get_dec_output_file(output_path)
            # Determine cipher from configuration
            cipher_name = self.guess_cipher(info) or info.get("cipher", None)

            if cipher_name:
                cipher = CipherFactory.CIPHERS.get(cipher_name)
            else:
                cipher = CipherFactory.CIPHERS.get(cipher)

            _data = self.decrypt(data=data, key=key, cipher=cipher, info=info)

        else:
            raise UserError("Invalid action provided")

        self.write_file(output_path, _data, "wb")
        self.processed_items += 1
        return output_path, self.processed_items

    def process_dir(
        self,
        path: Path,
        passphrase: str,
        action: PyLockerAction,
        cipher: Ciphers = Ciphers.AES256GCMCipher,
        compress: bool = False,
        output_path: Path = None,
    ):
        path = path.expanduser().absolute()
        if path.is_file() and passphrase:
            self.process_file(
                path, passphrase, action, cipher, action, compress, output_path
            )

        files = self.fs.collect_files(path)

        @decorators.for_loop(files)
        def process(file):
            self.process_file(
                Path(file), passphrase, action, cipher, compress, output_path
            )
            self.processed_items += 1

        return path, self.processed_items

    def get_enc_output_file(self, path: Path):
        return path.absolute().parent / f"{path.name}.plocked"

    def get_dec_output_file(self, path: Path):
        return path.absolute().parent / f"{path.name}".strip(".plocked")

    def encrypt_file(
        self,
        path,
        passphrase,
        cipher=None,
        output_path=None,
        compress=False,
    ):
        """Encrypt a file with explicit parameters."""
        return self.process_file(
            action=PyLockerAction.ENCRYPT,
            path=path,
            passphrase=passphrase,
            cipher=cipher,
            output_path=output_path,
        )

    def encrypt_directory(
        self, path, passphrase, cipher=None, output_path=None, compress=False
    ):
        """Encrypt a file with explicit parameters."""
        return self.process_dir(
            action=PyLockerAction.ENCRYPT,
            path=path,
            compress=False,
            passphrase=passphrase,
            cipher=cipher,
            output_path=output_path,
        )

    def decrypt_file(
        self,
        path,
        passphrase,
        cipher=None,
        output_path=None,
    ):
        """Encrypt a file with explicit parameters."""
        return self.process_file(
            passphrase=passphrase,
            action=PyLockerAction.DECRYPT,
            path=path,
            compress=False,
            cipher=cipher,
            output_path=output_path,
        )

    def decrypt_directory(
        self,
        path,
        passphrase,
        cipher=None,
        output_path=None,
    ):
        """Encrypt a file with explicit parameters."""
        return self.process_file(
            passphrase=passphrase,
            action=PyLockerAction.DECRYPT,
            path=path,
            cipher=cipher,
            output_path=output_path,
        )

    @property
    def __state__(self):
        return self.processed_items
