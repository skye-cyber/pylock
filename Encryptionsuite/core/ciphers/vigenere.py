from ..interfaces import Ciphers
from ...utils.decorators import decorators


class Vigenere(Ciphers):
    def __init__(
        self,
        key: str,
        handle_non_alpha: bool = True,
        preserve_case: bool = True,
    ):

        self.key = key.lower().replace(" ", "")
        self.handle_non_alpha = handle_non_alpha
        self.preserve_case = preserve_case

    @staticmethod
    def validate_key(key: str):
        if not all([c.isalpha() for c in key]) or len(key) < 1:
            # TODO Trasform numeric to alpha instead of throwing an error
            raise ValueError("VigenereCipher only accepts alphabetical keys")

    def clean_key(key: str) -> str:
        return key.lower().replace(" ", "")

    def encrypt(self, data: str) -> str:
        key = self.clean_key(self.key)
        self.validate_key(key)

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
        key = self.clean_key(self.key)
        self.validate_key(key)

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
