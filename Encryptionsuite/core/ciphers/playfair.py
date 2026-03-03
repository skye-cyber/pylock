from ..interfaces import Ciphers


class Playfair(Ciphers):
    def __init__(self, key: str):
        self.key = key

    @staticmethod
    def prepare_key(key: str):
        """
        Prepares the key for the Playfair Cipher.
        Removes duplicates, converts the key to uppercase, and handles 'J' as a separate character.
        """
        key = "".join(set(key.upper()))
        return key

    @staticmethod
    def create_matrix(key):
        """
        Creates the 5x5 Playfair Cipher matrix.
        """
        matrix = []
        remaining_letters = [chr(i) for i in range(65, 91) if chr(i) not in key]
        for char in key + "".join(remaining_letters):
            if len(matrix) == 0 or len(matrix[-1]) == 5:
                matrix.append([])
            matrix[-1].append(char)
        return matrix

    def encrypt(self, data: str) -> str:
        """
        Encrypts the plaintext using the Playfair Cipher.
        Handles repeated letters in the plaintext by inserting 'X' between them.
        """

        prepared_key = self.prepare_key(self.key)
        matrix = self.create_matrix(prepared_key)
        ciphertext = ""

        plaintext = "".join(char for char in data.upper() if char.isalpha())

        pairs = []

        for i in range(0, len(plaintext), 2):
            pair = plaintext[i : i + 2]
            if len(pair) == 1:
                pair += "X"
            elif pair[0] == pair[1]:
                pair = pair[0] + "X" + pair[1]
            pairs.append(pair)
        for pair in pairs:
            row1, col1 = None, None
            row2, col2 = None, None
            for i in range(5):
                for j in range(5):
                    if matrix[i][j] == pair[0]:
                        row1, col1 = i, j
                    elif matrix[i][j] == pair[1]:
                        row2, col2 = i, j
            if row1 == row2:
                ciphertext += (
                    matrix[row1][(col1 + 1) % 5] + matrix[row2][(col2 + 1) % 5]
                )
            elif col1 == col2:
                ciphertext += (
                    matrix[(row1 + 1) % 5][col1] + matrix[(row2 + 1) % 5][col2]
                )
            else:
                ciphertext += matrix[row1][col2] + matrix[row2][col1]
        return ciphertext

    def decrypt(self, data: str) -> str:
        """
        Decrypts the ciphertext using the Playfair Cipher.
        """
        prepared_key = self.prepare_key(self.key)
        matrix = self.create_matrix(prepared_key)

        plaintext = ""

        ciphertext = "".join(char for char in data.upper() if char.isalpha())

        pairs = [ciphertext[i : i + 2] for i in range(0, len(ciphertext), 2)]

        for pair in pairs:
            row1, col1 = None, None
            row2, col2 = None, None
            for i in range(5):
                for j in range(5):
                    if matrix[i][j] == pair[0]:
                        row1, col1 = i, j
                    elif matrix[i][j] == pair[1]:
                        row2, col2 = i, j
            if row1 == row2:
                plaintext += matrix[row1][(col1 - 1) % 5] + matrix[row2][(col2 - 1) % 5]
            elif col1 == col2:
                plaintext += matrix[(row1 - 1) % 5][col1] + matrix[(row2 - 1) % 5][col2]
            else:
                plaintext += matrix[row1][col2] + matrix[row2][col1]

            # Replace placeholder X with originall value
            f_result = ""
            for i in range(len(plaintext)):
                if i == 0 or plaintext[i] != "X":
                    f_result += plaintext[i]
                else:
                    f_result += plaintext[i - 1]
        return f_result.lower()

    def is_data_compartible(self, data) -> bool:
        """
        Check if data if compartbile with ciphere ie should be text data not bytes
        """
        return isinstance(data, str)
