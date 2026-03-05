import base64
from typing import Optional
from ..core.interfaces import CipherInterface
from ..utils.decorators import decorators, cipher
from ..core.exceptions import ValidationError


@cipher()
class Vigenere(CipherInterface):
    def __init__(
        self,
        key: Optional[bytes] = None,
        handle_non_alpha: bool = True,
        preserve_case: bool = True,
    ):
        """
        Vigenère polyalphabetic substitution cipher.

        Data compatibility: STRICTLY ASCII LETTERS ONLY (A-Z, case insensitive).
        No bytes, no unicode, no numbers, no spaces preserved.

        WARNING: Cryptographically broken - for educational/historical use only.
        """
        self.key = key
        self.handle_non_alpha = handle_non_alpha
        self.preserve_case = preserve_case

    @staticmethod
    def validate_key(key: str):
        if not all([c.isalpha() for c in key]) or len(key) < 1:
            # TODO Trasform numeric to alpha instead of throwing an error
            raise ValidationError("VigenereCipher only accepts alphabetical keys")

    def is_data_compatible(self, data: str) -> bool:
        if not isinstance(data, str):
            return False

        return True

    def clean_key(key: str) -> str:
        return key.lower().replace(" ", "")

    def encrypt(self, data: str) -> str:
        self.validate_key(self.key)

        result = []
        key_length = len(self.key)
        counter = 0

        @decorators.for_loop(data)
        def process(symbol, counter=counter):
            if symbol.isalpha():
                num = ord(symbol.lower())
                key_num = ord(self.key[counter % key_length]) - ord("a")

                num = (num - ord("a") + key_num) % 26 + ord("a")

                encoded = chr(num)

                if self.preserve_case and symbol.isupper():
                    encoded = encoded.upper()

                result.append(encoded)
                counter += 1
            else:
                # Preserve spacing and other characters eg punctuations
                result.append(symbol)

        result = "".join(result)
        return result

    def decrypt(self, data: str) -> str:
        self.validate_key(self.key)

        result = []
        key_length = len(self.key)
        counter = 0

        @decorators.for_loop(data)
        def process(symbol, counter=counter):
            if symbol.isalpha():
                num = ord(symbol.lower())
                key_num = ord(self.key[counter % key_length]) - ord("a")

                num = (num - ord("a") - key_num) % 26 + ord("a")

                encoded = chr(num)

                if self.preserve_case and symbol.isupper():
                    encoded = encoded.upper()

                result.append(encoded)
                counter += 1
            else:
                # Preserve spacing and other characters eg punctuations
                result.append(symbol)

        result = "".join(result)
        return result

    def is_data_compartible(self, data: str | bytes) -> bool:
        """
        Check if data if compartbile with ciphere ie should be text data not bytes
        """
        return isinstance(data, str)
