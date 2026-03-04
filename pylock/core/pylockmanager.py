"""Core encryption Logic: Integrated"""

import json
from pathlib import Path
from .pylock import BaseEncryptor
from .models import PyLockerAction
from ..utils.file_utils import FileSystemHandler
from ..utils.decorators import decorators


class PyLock(BaseEncryptor):
    def __init__(self, *args, **kwargs):
        self.fs = FileSystemHandler()
        self.processed_items = 0

        super.__init__(*args, **kwargs)

    def process_file(self, path: Path, key: str | bytes, action: PyLockerAction):
        """Encrypt a single file in-place with metadata header."""
        if path.is_dir() and key:
            self.process_dir(path, key)

        data = self.read_file()

        # Determine cipher from your configuration
        cipher = self.guess_cipher({}) or "fernet"
        # Set up metadata if needed
        self.write_metadata(
            json.dumps(
                {"original_name": path.name, "original_size": path.stat().st_size}
            )
        )
        encrypted_data = self.encrypt(data, key, cipher)
        self.write_file(
            path, encrypted_data, "wb"
        )  # f.write(base64.b64decode(ciphertext))
        self.processed_items += 1

    def process_dir(self, path: Path, key: str | bytes, action: PyLockerAction):
        if path.is_file() and key:
            self.process_file(path, key)

        files = self.fs.collect_files(path)

        @decorators.for_loop(files)
        def process(file):
            self.process_file(Path(file), key)
            self.processed_items += 1

    @property
    def __state__(self):
        return self.processed_items
