"""
PyLock - Modern File Encryption Suite

A beautiful, secure CLI tool for encrypting and decrypting files and folders.
"""

__version__ = "2.0.0"
__author__ = "Wambua (Skye-Cyber)"
__email__ = "swskye17@gmail.com"
__license__ = "GPL-3.0-or-later"

from .core.pylockmanager import PyLock
from .ciphers.factory import CipherFactory

__all__ = ["PyLock", "CipherFactory", "__version__"]
