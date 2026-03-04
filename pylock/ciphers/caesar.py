from ..core.interfaces import CipherInterface
from ..utils.decorators import cipher


@cipher()
class Caesar(CipherInterface):
    def __init__(self, key: int | str = 8):
        """Filter key type here to avoid error during initilization"""
        self.key = key if isinstance(key, int) and key >= 26 else 8

    def encrypt(self, data: str):
        """Encode the given message using the provided key."""
        result = ""
        for char in self.message:
            if char.isalpha():
                # Shift the character by the given key
                shifted_value = ord(char) + self.key
                # Handle uppercase and lowercase differently
                if char.isupper():
                    if shifted_value > ord("Z"):
                        shifted_value -= 26
                    elif shifted_value < ord("A"):
                        shifted_value += 26
                else:
                    if shifted_value > ord("z"):
                        shifted_value -= 26
                    elif shifted_value < ord("a"):
                        shifted_value += 26
                result += chr(shifted_value)
            else:
                # Leave non-alphabetical characters untouched
                result += char

        return result

    def decrypt(self, data: str):
        """Decode the given message using the provided key."""
        result = ""
        for char in data:
            if char.isalpha():
                # Reverse the shift by subtracting the key
                shifted_value = ord(char) - self.key
                # Handle uppercase and lowercase differently
                if char.isupper():
                    if shifted_value > ord("Z"):
                        shifted_value -= 26
                    elif shifted_value < ord("A"):
                        shifted_value += 26
                else:
                    if shifted_value > ord("z"):
                        shifted_value -= 26
                    elif shifted_value < ord("a"):
                        shifted_value += 26
                result += chr(shifted_value)
            else:
                # Leave non-alphabetical characters untouched
                result += char
        return result

    def is_data_compartible(self, data: str | bytes) -> bool:
        """
        Check if data if compartbile with ciphere ie should be text data not bytes
        """
        return isinstance(data, str)
