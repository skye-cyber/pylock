import argparse
import logging
import logging.handlers
import os
import sys
from rich.logging import RichHandler
from .banner import _banner_
from .bruteforce import Bruteforce
from .ciphers import dec_control, enc_control
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
from .enc_dec import decrypt_file, decrypt_folder, encrypt_file, encrypt_folder
from .master_ED import HandleFiles, HandleFolders
from .mores_cipher import _dec_control_, _enc_control_

logging.basicConfig(
    level=logging.INFO,
    format="- [%(levelname)s] - %(message)s",
    handlers=[RichHandler(rich_tracebacks=True)],
)
logger = logging.getLogger(__name__)


def clean_Encfile(input_file):
    _orig_ = input_file
    for i in range(int(input_file[-1:]), -1, -1):
        file = f"{input_file[:-1]}{i}"
        while os.path.exists(file) and file != f"{input_file[:-1]}{_orig_[-1:]}":
            print(f"{FMAGENTA}Delete {BWHITE}{file}🚮{RESET}")
            os.remove(file)
            break


def _clean_Origfile_(input_file):
    _orig_ = input_file
    for i in range(int(input_file[-1:])):
        file = f"{input_file[:-1]}{i}"
        while os.path.exists(file) and file != f"{input_file[-1:]}{_orig_[-1:]}":
            print(f"{FMAGENTA}Delete {BWHITE}{file}🚮{RESET}")
            os.remove(file)
            break


def _clean_dir_(gdir, mode):
    try:
        # Delete all original files
        for root, dirs, files in os.walk(gdir):
            for file in files:
                _path_ = os.path.join(root, file)

                # Clean enc files
                if mode is True:
                    if _path_[:-1].endswith("enc") and os.path.exists(_path_[:-5]):
                        print(f"{FMAGENTA}Delete {BWHITE}{_path_}🚮{RESET}")
                        os.remove(_path_)

                # Clean original files
                if mode is False:
                    if not _path_[:-1].endswith("enc") and (
                        os.path.exists(_path_ + f".enc{0}")
                        or os.path.exists(_path_ + f".enc{1}")
                    ):
                        print(f"{FMAGENTA}Delete {BWHITE}{_path_}🚮{RESET}")
                        os.remove(_path_)

                    if (
                        _path_[:-1].endswith("enc")
                        and os.path.exists(_path_ + f".enc{0}")
                        and os.path.exists(_path_ + f".enc{1}")
                    ):
                        os.remove(_path_ + f".enc{0}")

    except Exception as e:
        print(f"{RED}{e}{RESET}")


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
        self._caesar_ = {"caesar", "caesar_cipher", "caesarcipher"}
        self._more_ = {"mores", "mores_cipher", "morescipher", "mores-cipher"}
        self._playfair_ = {"playfaircipher", "playfair"}

        self._secure_ = False

    def run(self):
        self.validator()

        if self.args.encrypt:
            status = self.encMapper()

        elif self.args.decrypt:
            status = self.decMapper()

        if status:
            logger.info(f"{DGREEN}====== END ======{RESET}")

    def handle_help(self):
        if not self.args or self.args.help:
            _banner_()
            self.parser.print_help()
            sys.exit(
                f"{CYAN}👉 Brutefore only supports non-cipher encrypted file{RESET}"
            )

    def validator(self):
        self.handle_help()
        if not self.args.input_file:
            sys.exit("The following arguments are required: -i/--input_file")
        if not any((self.args.encrypt, self.args.decrypt)):
            sys.exit(
                f"You need to specify operation: {DYELLOW}Encryption{RESET}/{DYELLOW}Decryption{RESET}"
            )

        if not os.path.exists(self.args.input_file):
            sys.exit(f"{BWHITE}File does not exist{RESET}")

        if not any(
            (
                self.args.random_key,
                self.args.passphrase,
                self.args.cipher,
                self.args.pass_list,
                self._secure_,
            )
        ):
            sys.exit(
                "An encryption passphrase is needed otherwise try the command again with '--Rk' flag to use a randomly generated encryption key"
            )
        return True

    @staticmethod
    def get_keys(pf) -> list[str]:
        with open(pf) as f:
            ps = f.read()
        return ps.split(",")

    def multiLevelEnc(self, pass_list, isfile=True):
        def _exec(file, key):
            if isfile:
                enc_control(file, self.args.cipher, key)
            else:
                init = HandleFolders(file, key)
                init.encrypt_folder()

        e_level = 0

        input_file = self.args.input_file
        for pass_key in pass_list:
            _exec(input_file, pass_key)
            input_file = (
                f"{input_file}.enc{e_level}"
                if input_file[-4:-1] != "enc"
                else f"{input_file[:-1]}{e_level}"
            )

            e_level += 1

        # Clean intermediary files
        _clean_Origfile_(input_file)

    def multiLevelDec(self, pass_list, isfile=True):
        def _exec(file, key):
            if isfile:
                dec_control(file, self.args.cipher, key)
            else:
                init = HandleFolders(file, key)
                init.decrypt_folder()

        e_level = 0

        input_file = self.args.input_file
        for pass_key in pass_list:
            _exec(input_file, pass_key)
            input_file = (
                f"{input_file}.enc{e_level}"
                if input_file[-4:-1] != "enc"
                else f"{input_file[:-1]}{e_level}"
            )

            e_level += 1

        # Clean intermediary files
        clean_Encfile(input_file)

    """Hnadle All Encryption operations"""

    def encMapper(self):
        _map = {
            self.args.cipher: self.cipherEnc,
            os.path.isfile(self.args.input_file)
            and any((self.args.passphrase, self.args.pass_list)): self.encFile,
            os.path.isdir(self.args.input_file)
            and any((self.args.passphrase, self.args.pass_list)): self.encDir,
        }
        method = next((_map[key] for key in _map if key), None)
        if method:
            status = method()
            if status:
                logger.info(f"Encryption {DGREEN}Done")
                return True

    def cipherEnc(self):
        logger.info(
            f"{DGREEN}======START@Encryption:{DYELLOW}Target:{BLUE}Dir{GREEN}======{RESET}"
        )

        def validate():
            if self.args.cipher not in (
                self._caesar_.union(self._more_, self._playfair_)
            ):
                logger.setLevel("CRITICAL")
                logger.critical(f"\033[95m{self.args.cipher}\033[0m cipher not found")
                sys.exit(2)

            if not self.args.passphrase and self.args.cipher.lower() in self._playfair_:
                sys.exit("Please provide passphrase")

            return True

        try:
            if validate():
                if self.args.cipher.lower() in set(self._more_):
                    _enc_control_(self.args.input_file)
                elif self.args.cipher.lower() in set(self._caesar_):
                    enc_control(self.input_file, cipher=None, key=None)

                elif self.args.pass_list:
                    self.multiLevelEnc(
                        self.get_keys(self.args.pass_list)
                        if os.path.exists(self.args.pass_list)
                        else list(self.args.pass_list)
                    )
                elif self.args.passphrase:
                    logger.info(f"{BWHITE}@key={CGREEN}{self.passphrase}{RESET}")
                    enc_control(self.input_file, self.args.cipher, self.args.passphrase)
                    return True
        except Exception:
            return False

    def encFile(self):
        logger.info(f"{DGREEN}======START@Encryption======{RESET}")
        try:
            if self.args.pass_list:
                self.multiLevelEnc(
                    self.get_keys(self.args.pass_list)
                    if os.path.exists(self.args.pass_list)
                    else list(self.args.pass_list)
                )
            elif self.args.passphrase:
                init = HandleFiles(self.args.input_file, self.args.passphrase)
                init.encrypt_file()

            # Handle case where passphrase is not provided but random key is provided

            elif self.args.random_key:
                encrypt_file(self.args.input_file)
        finally:
            pass  # _clean_Origfile_(self.args.input_file)

    def encDir(self):
        logger.info(f"{DGREEN}======START@{BLUE}DIR-{GREEN}Encryption======{RESET}")
        try:
            if self.args.pass_list:
                self.multiLevelEnc(
                    self.get_keys(self.args.pass_list)
                    if os.path.exists(self.args.pass_list)
                    else list(self.args.pass_list),
                    isfile=False,
                )
            elif self.args.passphrase:
                logger.info(
                    f"{BWHITE}@key length={CGREEN}{len(self.args.passphrase)}{RESET}"
                )
                init = HandleFolders(self.args.input_file, self.args.passphrase)
                init.encrypt_folder()

            # Handle case where passphrase is not provided but random key is provided

            elif self.args.random_key:
                encrypt_folder(self.args.input_file)
        finally:
            # Clean original files from the directory
            _clean_dir_(self.args.input_file, False)

    """Hnadle All Decryption operations"""

    def decMapper(self):
        _map = {
            self.args.cipher: self.cipherDec,
            self.args.bruteforce: self.BruteforceDec,
            os.path.isfile(self.args.input_file)
            and any((self.args.passphrase, self.args.pass_list)): self.decFile,
            os.path.isdir(self.args.input_file)
            and any((self.args.passphrase, self.args.pass_list)): self.decDir,
        }
        method = next((_map[key] for key in _map if key), None)
        if method:
            status = method()
            if status:
                logger.info(f"Decryption {DGREEN}Done")
                return True

    def BruteforceDec(self):
        init = Bruteforce(self.args.input_file, self.args.bruteforce)
        init.conservative()

    def cipherDec(self):
        logger.info(
            f"{DGREEN}======START@Decryption:{DYELLOW}Target:{BLUE}Dir{GREEN}======{RESET}"
        )

        def validate():
            if self.args.cipher not in (
                self._caesar_.union(self._more_, self._playfair_)
            ):
                logger.setLevel("CRITICAL")
                logger.critical(f"\033[95m{self.args.cipher}\033[0m cipher not found")
                sys.exit(2)

            if not self.args.passphrase and self.args.cipher.lower() in self._playfair_:
                sys.exit("Please provide passphrase")

            return True

        try:
            if validate():
                if self.args.cipher.lower() in set(self._more_):
                    _dec_control_(self.args.input_file)
                elif self.args.cipher.lower() in set(self._caesar_):
                    dec_control(self.input_file, cipher=None, key=None)

                elif self.args.pass_list:
                    self.multiLevelDec(
                        self.get_keys(self.args.pass_list)
                        if os.path.exists(self.args.pass_list)
                        else list(self.args.pass_list)
                    )
                elif self.args.passphrase:
                    logger.info(f"{BWHITE}@key={CGREEN}{self.passphrase}{RESET}")
                    dec_control(self.input_file, self.args.cipher, self.args.passphrase)
                    return True
        except Exception:
            return False

    def decFile(self):
        logger.info(f"{DGREEN}======START@Decryption======{RESET}")

        try:
            if self.args.pass_list:
                self.multiLevelDec(
                    self.get_keys(self.args.pass_list)
                    if os.path.exists(self.args.pass_list)
                    else list(self.args.pass_list)
                )
            elif self.args.passphrase:
                init = HandleFiles(self.args.input_file, self.args.passphrase)
                init.decrypt_file()

            # Handle case where passphrase is not provided but random key is provided

            elif self.args.random_key:
                decrypt_file(self.args.input_file)
        finally:
            pass  # _clean_Origfile_(self.args.input_file)

    def decDir(self):
        logger.info(f"{DGREEN}======START@{BLUE}DIR-{GREEN}Decryption======{RESET}")
        try:
            if self.args.pass_list:
                self.multiLevelEnc(
                    self.get_keys(self.args.pass_list)
                    if os.path.exists(self.args.pass_list)
                    else list(self.args.pass_list),
                    isfile=False,
                )
            elif self.args.passphrase:
                logger.info(
                    f"{BWHITE}@key length={CGREEN}{len(self.args.passphrase)}{RESET}"
                )
                init = HandleFolders(self.args.input_file, self.args.passphrase)
                init.decrypt_folder()

            # Handle case where passphrase is not provided but random key is provided

            elif self.args.random_key:
                decrypt_folder(self.args.input_file)
        finally:
            # Clean original files from the directory
            _clean_dir_(self.args.input_file, False)


if __name__ == "__main__":
    ArgsMain()
