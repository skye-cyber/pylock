"""
Lock manager for operation as file handling is sensitive
"""

from .interfaces import LockInterface


class LockManager(LockInterface):
    """Operations Lock manager"""
