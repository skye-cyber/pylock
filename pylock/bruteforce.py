import logging
import logging.handlers
import os
import shutil
import sys
from fnmatch import fnmatch

from .colors import BBWHITE, BWHITE, CGREEN, CYAN, FCYAN, DGREEN, FMAGENTA, RED, RESET
from cryptography.fernet import Fernet
from .master_ED import HandleFiles

logging.basicConfig(level=logging.INFO, format='%(levelname)-8s %(message)s')
logger = logging.getLogger(__name__)

# import pyperclip


class CryptoDom:
    def __init__(self, obj: str, key):
        self.obj = obj
        self.key = key

    def decrypt_file(self):

        try:
            # Ensure the key is of type bytes
            key = HandleFiles.generate_enc_key(self.key)
            cipher = Fernet(key)

            # open the file for decryption
            with open(self.obj, 'rb') as file:
                encrypted_data = file.read()

            decrypted_data = cipher.decrypt(encrypted_data)

            # Extract encryption infor from the encrypted file for decide on appropriate file name
            file = self.obj
            # print("\033[1;35mRestore file name{RESET}")
            e_level = int(file[-1:]) - 1 if file[-4:-
                                                 1] == 'enc' and int(file[-1:]) != 0 else ''
            fname = f'{file[:-1]}{e_level}' if e_level != '' else file[:-5]
            with open(fname, 'wb') as file:
                file.write(decrypted_data)

        except KeyboardInterrupt:
            print("\nQuit!")
            sys.exit(1)

        except BaseException as e:
            print(f"{RED}{e}{RESET}")

        except Exception as e:
            logger.error(f"{RED}{e}{RESET}")
            print(f"{RED}Decryption failure.{RESET}\n")
        else:
            logger.info(
                f"{BWHITE} File Decrypted successfully as {BWHITE}{fname}{RESET}")
            return True


class Bruteforce:
    def __init__(self, obj, dict_file):
        self.obj = obj
        self.dict_file = dict_file

        if not os.path.exists(self.obj):
            print(f"{RED}[Error] File Not Found { self.obj}{RESET}")
            sys.exit(1)
        if not os.path.exists(self.dict_file):
            print(f"{RED}[Error] File Not Found {self.dict_file}{RESET}")
            sys.exit(1)

        # logger.info(F"{DGREEN}======START@Deryption======{RESET}")

    def conservative(self):
        # Critical redundacy
        # Goal:-> Is to avoid loosing the original files by Creating temporary directory to store temporary files

        def SafeClean():
            logger.info(f"{DGREEN} ======END======{RESET}")

            def ignore_files(directory, files, patterns: str):
                ignored = []
                for file in files:
                    for pattern in patterns:
                        if fnmatch(file[:-1], pattern):
                            ignored.append(file)
                return ignored

            print(f"{FMAGENTA}SafeClean{RESET}")
            try:
                _par_dir_ = os.path.dirname(self.obj)
                CRDIR = os.path.join(_par_dir_, "CRDIR")
                if os.path.isfile(self.obj):
                    _flname = os.path.split(_fpath)[-1]
                    _dec_fl = os.path.join(CRDIR, _flname[:-5])

                    # Copy decrypted content to the original directory
                    shutil.copy2(_dec_fl, _par_dir_)
                    shutil.rmtree(CRDIR)

                elif os.path.isdir(self.obj):
                    # _temp_ = self.obj
                    folder = os.path.split(self.obj)[-1] + 'dec'
                    _target_dir_ = os.path.join(_par_dir_, folder)
                    if os.listdir(_dir) != 0:
                        for root, dirs, files in os.walk(CRDIR):
                            for file in files:
                                if file[-4:-1] == 'enc':

                                    os.remove(os.path.join(root, file))

                        # patterns = [r".*\.enc\d*"]
                        # shutil.copytree(_temp_, _target_dir_, ignore = lambda dir, files: _ignore_enc_files(files))
                        shutil.copytree(
                            CRDIR, _target_dir_, symlinks=True)

                        shutil.rmtree(CRDIR)
                    else:
                        os.remove(CRDIR)

            except KeyboardInterrupt:
                print("\nQuit!")
                sys.exit(1)
            except OSError as e:
                print(f"{RED}{e}{RESET}")
            except FileExistsError as e:
                print(f"{RED}{e}{RESET}")
            except FileNotFoundError as e:
                print(f"{RED}{e}{RESET}")
            except Exception as e:
                print(f"{RED}{e}{RESET}")
            else:
                print(f"{BBWHITE}Saved as => {_target_dir_}{RESET}")
                print("✅")

        if os.path.isfile(self.obj):
            try:
                _file = os.path.split(self.obj)[-1]
                _path = os.path.dirname(self.obj)
                _dir = os.path.join(_path, "CRDIR")
                # Create temporary directory
                if os.path.exists(_dir) and not os.listdir(_dir):
                    os.rmdir(_dir)
                if not os.path.exists(_dir):
                    os.mkdir(_dir)
                    # cmd = f"cp -r {self.obj} {_dir}" if os.name == 'posix' else f"copy -r {self.obj} {_dir}"
                    shutil.copy(self.obj, _dir)
                # Call file bruteforce function
                _fpath = os.path.join(_dir, _file)
                if not _fpath[:-1].endswith('enc'):
                    logger.exception(
                        f"{FCYAN}File Does Not appear to be Encryted{RESET}")
                # Open dictionary file for Bruteforce
                with open(self.dict_file, 'r') as df:
                    passw = df.readlines()

                # pass_ls = []
                # i = 0
                for ps in passw:
                    # i += 1
                    key = ''
                    for char in ps.lstrip():
                        if char == '\n':
                            continue
                        key += char
                    # pass_ls.append(key)
                    print(f"{CGREEN}{key}{RESET}", end='\r')
                    # Create decryption object
                    init = CryptoDom(_fpath, key)
                    req = init.decrypt_file()
                    if req is True:
                        logger.info(
                            F"{DGREEN}<-@key-> {RESET}{BBWHITE}{key}{RESET}")
                        SafeClean()
                        sys.exit(0)
                else:
                    print(f"{RED}key Not Found{RESET}")
                    sys.exit(1)

            except KeyboardInterrupt:
                print("\nQuit!")
                sys.exit(1)
            except FileExistsError as e:
                print(f"{RED}{e}{RESET}")
            except FileNotFoundError as e:
                print(f"{RED}{e}{RESET}")

        elif os.path.isdir(self.obj):
            try:
                _path = os.path.dirname(self.obj)
                _dir = os.path.join(_path, "CRDIR")
                # Create temporary directory
                # if os.path.exists(_dir) and len(os.listdir(_dir)) == 0:
                if os.path.exists(_dir):
                    shutil.rmtree(_dir)

                # os.mkdir(_dir)
                # cmd = f"cp -r {self.obj} {_dir}" if os.name == 'posix' else f"copy -r {self.obj} {_dir}"
                shutil.copytree(self.obj, _dir)

                # Open dictionary file for Bruteforce
                with open(self.dict_file, 'r') as df:
                    passw = df.readlines()

                req = None
                cracked = False
                for root, dirs, files in os.walk(_dir):
                    for file in files:

                        if file[:-1].endswith("enc"):
                            print(f"{CYAN}Bruteforce{RESET} {file}")
                            _path = os.path.join(root, file)
                            # pass_ls = []

                            if cracked is True:
                                init = CryptoDom(_path, key)
                                req = init.decrypt_file()
                            else:
                                # i = 0
                                for ps in passw:
                                    # i += 1
                                    key = ''
                                    for char in ps.lstrip():
                                        if char == '\n':
                                            continue
                                        key += char
                                    # pass_ls.append(key)

                                    print(f"{CGREEN}{key}{RESET}", end='\r')
                                    # Create decryption object
                                    init = CryptoDom(_path, key)
                                    req = init.decrypt_file()
                                    if req is True:
                                        logger.info(
                                            F"{DGREEN}Found Key -> {RESET}{BBWHITE}{key}{RESET}")
                                        cracked = True
                                        break

                            if cracked:
                                continue
                            else:
                                print(f"{RED}key Not Found{RESET}")
                                sys.exit(1)
                if req is True:
                    SafeClean()
                sys.exit(0)

            except KeyboardInterrupt:
                print("\nQuit!")
                sys.exit(1)
            except AttributeError as e:
                print(f"{RED}{e}{RESET}")
            except FileExistsError as e:
                print(f"{RED}{e}{RESET}")
            except FileNotFoundError as e:
                print(f"{RED}{e}{RESET}")


if __name__ == "__main__":
    init = Bruteforce("/home/skye/Desktop/Test/ALetter.docx.enc0",
                      "/home/skye/Documents/jo.txt")
    init.conservative()
