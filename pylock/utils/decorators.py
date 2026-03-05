from typing import Type
from ..ciphers.cipher_model import CIPHERS
from ..core.interfaces import Cipher


class Decorators:
    def __init__(self):
        pass

    @staticmethod
    def for_loop(data_list):
        """
        A decorator that calls the decorated function with each element
        from the provided list or tuple.

        Args:
            data_list: A list or tuple of data to iterate over.
        """

        def decorator(func):
            def wrapper(self, *args, **kwargs):
                for item in data_list:
                    func(self, item, *args, **kwargs)

            return wrapper

        return decorator


def cipher(name: str = None):
    def decorator(cls: Type[Cipher]):
        # Use class name or provided name
        key = name or cls.__name__.lower()
        CIPHERS[key] = cls
        return cls

    return decorator


decorators = Decorators()

__all__ = ["Decorators", "decorators"]
