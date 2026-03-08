"""
File utility functions for encryptionsuite.
"""

import fnmatch
import os
import shutil
import tempfile
import uuid
from pathlib import Path
from typing import Iterator, List, Optional, Union, Tuple
from tqdm.auto import tqdm
from ..core.exceptions import FileSystemError
from .colors import OutputFormater as OF
from .logging import simplelogger as logger


def dirbuster(dir: str, suffixes: Union[List, Tuple]) -> list:
    try:
        target = []
        for root, dirs, files in os.walk(dir):
            for file in files:
                ext = file.split(".")[-1]

                path = os.path.join(root, file)
                if os.path.exists(path) and (
                    ext.lower() in suffixes if suffixes else True
                ):
                    target.append(path)
        return target
    except FileNotFoundError as e:
        print(e)

    except KeyboardInterrupt:
        print("\nQuit!")
        return


def generate_filename(
    basedir: Path, suffix: str, postfix: Optional[str] = "suite"
) -> Path:
    """
    Generate Filename given its extension
    Args:
        suffix-> str file extension
        basedir-> Path
        postfix = str string preceding name
        prefix - string before name
    Returns:
        path
    """

    filename = basedir / f"{uuid.uuid4().hex}-{postfix}.{suffix}"

    return filename


class FileSystemHandler:
    """
    Encapsulates file handling utilities required by cleaner
    """

    def __init__(self, ignore: Optional[List | tuple] = None):
        self.ignore = ignore

    def find_files(self, paths, patterns, recursive=True) -> List:
        try:
            candidates = []
            for path in paths:
                path_obj = Path(path).expanduser().resolve()
                if not path_obj.exists():
                    continue
                if recursive:
                    for file in tqdm(
                        path_obj.rglob("*"), desc="Searching", leave=False
                    ):
                        if file.is_file() and any(
                            fnmatch.fnmatch(file.name, pat) for pat in patterns
                        ):
                            candidates.append(file)
                else:
                    for file in tqdm(path_obj.glob("*"), desc="Searching", leave=False):
                        if file.is_file() and any(
                            fnmatch.fnmatch(file.name, pat) for pat in patterns
                        ):
                            candidates.append(file)
            return self.ignore_pattern(candidates)
        except Exception as e:
            raise FileSystemError(e)

    def find_directories(self, paths, patterns, recursive=True, empty=True) -> list:
        try:
            candidates = []
            for path in paths:
                path_obj = Path(path).expanduser().resolve()
                if not path_obj.exists():
                    continue
                if recursive:
                    for root, dirs, files in tqdm(
                        os.walk(path_obj, followlinks=True),
                        desc="Searching",
                        leave=False,
                    ):
                        for dir in dirs:
                            if len(os.listdir(os.path.join(root, dir))) == 0:
                                candidates.append(Path(root) / dir)

                else:
                    for item in tqdm(
                        os.listdir(path_obj), desc="Searching", leave=False
                    ):
                        if os.path.isdir(item) and len(os.listdir(item)) == 0:
                            candidates.append(path_obj / item)

            return self.ignore_pattern(candidates)
        except Exception as e:
            raise FileSystemError(e)

    def ignore_pattern(self, items: List | tuple, ignore: List | tuple = None) -> List:
        ignore = self.ignore if not ignore else ignore
        candidates = []
        for item in items:
            for ig in ignore:
                _ig = ig.lower()
                if _ig in item.as_uri().lower().split(
                    "/"
                ) + item.as_uri().lower().split("\\"):
                    continue

            candidates.append(item)

        return candidates

    @staticmethod
    def _find_files(pattern: str, recursive: bool = True) -> Iterator[Path]:
        """Find files matching pattern."""
        path = Path(pattern)

        if path.exists() and path.is_file():
            yield path
            return

        # Handle glob patterns
        if recursive:
            yield from Path(".").rglob(pattern)
        else:
            yield from Path(".").glob(pattern)

    @staticmethod
    def delete_files(files: List[Path], verbose: bool = False) -> bool:
        try:
            for f in files:
                if f.exists():
                    f.unlink()
                    if verbose:
                        print(f"{OF.OK} Deleted: {f}")
            return True
        except (PermissionError, OSError) as e:
            raise FileSystemError(e)
        except Exception as e:
            print(f"{OF.ERR} Failed to delete {f}: {e}")
            return False

    @staticmethod
    def delete_folders(files: List[Path]) -> bool:
        try:
            for f in files:
                if f.exists():
                    f.rmdir()
                    print(f"{OF.OK} Deleted: {f}")
            return True
        except (PermissionError, OSError) as e:
            raise FileSystemError(e)
        except Exception as e:
            print(f"{OF.ERR} Failed to delete {f}: {e}")
            return False

    @staticmethod
    def ensure_directory(path: Path) -> Path:
        """Ensure directory exists, create if necessary."""
        try:
            path.mkdir(parents=True, exist_ok=True)
            return path
        except OSError as e:
            raise FileSystemError(f"Failed to create directory {path}: {str(e)}")

    @staticmethod
    def safe_filename(name: str, max_length: int = 255) -> str:
        """Convert string to safe filename."""
        # Replace unsafe characters
        safe_name = "".join(c if c.isalnum() or c in "._- " else "_" for c in name)

        # Remove extra spaces and underscores
        safe_name = "_".join(filter(None, safe_name.split()))

        # Trim to max length
        if len(safe_name) > max_length:
            name_hash = str(hash(safe_name))[-8:]
            safe_name = safe_name[: max_length - 9] + "_" + name_hash

        return safe_name

    @staticmethod
    def collect_files(path: Path):
        """
        Get file path list given dir/folder

        -------
        Args:
            path: path to the directory/folder
        Returns:
        -------
            list
        """
        str_path = path.as_posix()

        files = [os.path.join(str_path, f) for f in os.listdir(str_path)]
        if not files:  # Check for empty directory *after* filtering
            raise FileNotFoundError(f"No supported image files found in: {str_path}")
        return files


class TemporaryFileManager:
    """Manages temporary files with proper cleanup."""

    def __init__(self, prefix: str = "suite_"):
        self.temp_files = []
        self.temp_dirs = []
        self.prefix = prefix

    def create_temp_file(self, suffix: str, content: str = "") -> Path:
        """Create a temporary file with the given suffix and content."""
        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                suffix=suffix,
                prefix=self.prefix,
                encoding="utf-8",
                delete=False,
            ) as f:
                if content:
                    f.write(content)
                temp_path = Path(f.name)

            self.temp_files.append(temp_path)
            return temp_path

        except (OSError, IOError) as e:
            raise FileSystemError(f"Failed to create temporary file: {str(e)}")

    def create_temp_dir(self) -> Path:
        """Create a temporary directory."""
        try:
            temp_dir = Path(tempfile.mkdtemp(prefix=self.prefix))
            self.temp_dirs.append(temp_dir)
            return temp_dir
        except OSError as e:
            raise FileSystemError(f"Failed to create temporary directory: {str(e)}")

    def cleanup(self):
        """Clean up all temporary files and directories."""
        for temp_file in self.temp_files:
            try:
                if temp_file.exists():
                    temp_file.unlink()
            except OSError as e:
                logger.warning(f"Failed to delete temporary file {temp_file}: {e}")

        for temp_dir in self.temp_dirs:
            try:
                if temp_dir.exists():
                    shutil.rmtree(temp_dir)
            except OSError as e:
                logger.warning(f"Failed to delete temporary directory {temp_dir}: {e}")

        self.temp_files.clear()
        self.temp_dirs.clear()


def modify_filename_if_exists(filename):
    """
    Modifies the filename by adding "_filewarp" before the extension if the original filename exists.

    Args:
        filename (str): The filename to modify.

    Returns:
        str: The modified filename, or the original filename if it doesn't exist or has no extension.
    """
    if os.path.exists(filename):
        parts = filename.rsplit(".", 1)  # Split from the right, at most once
        if len(parts) == 2:
            base, ext = parts
            return f"{base}_suite.{ext}"
        else:
            return f"{filename}_suite"  # handle files with no extension.
    else:
        return filename
