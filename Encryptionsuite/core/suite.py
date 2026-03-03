"""Core encryption Logic: Integrated"""

from pathlib import Path
from .base import BaseEncryptor
from .models import SuiteAction
from ..utils.file_utils import FileSystemHandler
from ..utils.decorators import decorators


class Suite(BaseEncryptor):
    def __init__(self, *args, **kwargs):
        self.fs = FileSystemHandler()
        self.processed_items = 0

        super.__init__(*args, **kwargs)

    def process_file(self, path: Path, key: str | bytes, action: SuiteAction):
        if path.is_dir() and key:
            self.process_dir(path, key)

        data = self.read_file()
        encrypted_data = self[action](data)
        self.write_file(path, encrypted_data, "wb")
        self.processed_items += 1

    def process_dir(self, path: Path, key: str | bytes, action: SuiteAction):
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
