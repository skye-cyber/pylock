from .ase256gsm import AES256GCMCipher
from .chacha20 import ChaCha20Cipher
from .rsa import RSACipher
from .hybridrsa_aes import HybridRSAAESCipher
from ..core.interfaces import CipherInterface
from .onetimepad import OneTimePadCipher
from .vigenere import Vigenere
from .fernet import Fernet


class CipherFactory:
    """Factory for creating cipher instances."""

    CIPHERS = {
        "aes-256-gcm": AES256GCMCipher,
        "chacha20": ChaCha20Cipher,
        "otp": OneTimePadCipher,
        "rsa": RSACipher,
        "vigenere": Vigenere,
        "hybrid-rsa-aes": HybridRSAAESCipher,
        "fernet": Fernet,
    }

    @classmethod
    def create(cls, name: str, **kwargs) -> CipherInterface:
        """Create cipher by name."""
        name = name.lower().replace("_", "-")
        if name not in cls.CIPHERS:
            raise ValueError(
                f"Unknown cipher: {name}. Available: {list(cls.CIPHERS.keys())}"
            )
        return cls.CIPHERS[name](**kwargs)

    @classmethod
    def list_ciphers(cls) -> dict:
        """List available ciphers and their properties."""
        return {
            name: {
                "class": cipher_class.__name__,
                "secure": name
                not in ("vigenere", "otp"),  # OTP secure if used correctly
                "notes": cipher_class.__doc__.strip().split("\n")[0]
                if cipher_class.__doc__
                else "",
            }
            for name, cipher_class in cls.CIPHERS.items()
        }


#
# if __name__ == "__main__":
#     # Test data
#     secret_message = "Hello, World! This is a secret."
#     short_message = "ATTACKATDAWN"
#
#     print("=" * 60)
#     print("Cipher Compatibility and Encryption Tests")
#     print("=" * 60)
#
#     # 1. AES-256-GCM
#     print("\n1. AES-256-GCM")
#     aes = AES256GCMCipher(password="my_secret_password")
#     print(
#         f"   Compatible with '{secret_message[:20]}...': {aes.is_data_compatible(secret_message)}"
#     )
#     encrypted = aes.encrypt(secret_message)
#     print(f"   Encrypted length: {len(encrypted)}")
#     decrypted = aes.decrypt(encrypted)
#     print(f"   Decrypted matches: {decrypted == secret_message}")
#
#     # 2. ChaCha20
#     print("\n2. ChaCha20-Poly1305")
#     chacha = ChaCha20Cipher()
#     print(f"   Compatible: {chacha.is_data_compatible(secret_message)}")
#     encrypted = chacha.encrypt(secret_message)
#     decrypted = chacha.decrypt(encrypted)
#     print(f"   Decrypted matches: {decrypted == secret_message}")
#
#     # 3. One-Time Pad (requires key generation)
#     print("\n3. One-Time Pad")
#     otp_key = os.urandom(len(short_message))  # Must be same length
#     otp = OneTimePadCipher(key=otp_key)
#     print(
#         f"   Compatible with '{short_message}': {otp.is_data_compatible(short_message)}"
#     )
#     print(
#         f"   Compatible with '{secret_message[:20]}...': {otp.is_data_compatible(secret_message)}"
#     )  # False (too long)
#     encrypted = otp.encrypt(short_message)
#     decrypted = otp.decrypt(encrypted)
#     print(f"   Decrypted matches: {decrypted == short_message}")
#
#     # 4. RSA (small data only)
#     print("\n4. RSA-OAEP-2048")
#     rsa = RSACipher(key_size=2048)
#     small_secret = "Key:ABC123"
#     print(
#         f"   Compatible with '{small_secret}' ({len(small_secret)} bytes): {rsa.is_data_compatible(small_secret)}"
#     )
#     print(
#         f"   Compatible with long message: {rsa.is_data_compatible(secret_message)}"
#     )  # False
#     encrypted = rsa.encrypt(small_secret)
#     decrypted = rsa.decrypt(encrypted)
