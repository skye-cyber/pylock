import argparse
import logging
import logging.handlers
import os
import sys
from .utils.logging import simple_logger as logger
from .banner import _banner_
from .bruteforce import Bruteforce
from .colors import (
    BWHITE,
    CGREEN,
    BLUE,
    CYAN,
    DGREEN,
    DYELLOW,
    FCYAN,
    FMAGENTA,
    GREEN,
    RED,
    RESET,
)
from .core.pylockmanager import PyLock


def ArgsMain():
    # create argument parser
    Note = f"{CYAN}Password option does not work for caesar_cipher and mores_cipher.{RESET}"
    parser = argparse.ArgumentParser(
        description="Encrypt or decrypt files and folders",
        epilog=Note + "\n",
        add_help=False,
    )
    # Define required arguments
    parser.add_argument(
        "-enc",
        "--encrypt",
        action="store_true",
        help="Encrypt file/folder",
    )

    parser.add_argument(
        "-dec",
        "--decrypt",
        action="store_true",
        help="Decrypt file/folder",
    )

    parser.add_argument(
        "-i", "--input_file", type=str, help="Input file path or folder"
    )

    parser.add_argument(
        "-Rk", "--random_key", type=str, help="decryption key to be used"
    )
    parser.add_argument(
        "-p",
        "--passphrase",
        type=str,
        help="Encryption/decryption passphrase/password to be used",
    )  # {DBLUE} Password(will be hidden){RESET}')
    parser.add_argument(
        "-c",
        "--cipher",
        help=f"cipher to be used, avaiable ciphers:\
        [\033[1;34mcaesar, PlayfairCipher, vigenere, mores_cipher{RESET}]",
    )

    parser.add_argument(
        "--pass_list",
        "-pl",
        help="""Provide passwords list or file containing password list for decryptiona and encryption""",
    )
    parser.add_argument(
        "-b",
        "--bruteforce",
        help="Run a list of words/passphrases against the file/folder to see which works.",
    )
    parser.add_argument(
        "-h", "--help", action="store_true", help="Show this help message and exit"
    )

    # Parse the commandline arguments
    init = argsOPMaper(parser)
    init.run()


class argsOPMaper:
    def __init__(self, parser) -> None:
        self.parser = parser
        self.args = parser.parse_args()
        self.pylock = PyLock()
        self.ciphers = self.pylock.

        self._secure_ = False

    def run(self):
        self.validator()

        self.pylock.encrypt(...)
        self.pylock.decrypt(...)


if __name__ == "__main__":
    ArgsMain()
