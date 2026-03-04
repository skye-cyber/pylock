import os
import time
import atexit
import signal
from pathlib import Path
from typing import Optional, Set, Dict
import json
import fcntl  # Unix-only; Windows alternative below
import errno
import psutil  # For cross-platform process checking
from .models import LockInfo
from .interfaces import LockInterface
from .exceptions import PermError, PyLockError, RuntimeError


class LockManager(LockInterface):
    """
    Process-safe lock manager for file operations.

    Uses PID-based lock files with automatic cleanup of stale locks.
    Thread-safe within process, process-safe across system.

    Lock file format: {target_path}.lock or {folder}/.operation.lock
    """

    LOCK_SUFFIX = ".lock"
    LOCK_DIR = ".locks"  # Subdirectory for lock files (optional)
    STALE_CHECK_TIMEOUT = 600  # 10 minutes - consider lock stale if older

    def __init__(
        self, lock_dir: Optional[Path] = None, use_stale_detection: bool = True
    ):
        """
        Initialize lock manager.

        Args:
            lock_dir: Directory to store lock files (default: same as target)
            use_stale_detection: Automatically break locks from dead processes
        """
        self.lock_dir = Path(lock_dir) if lock_dir else None
        self.use_stale_detection = use_stale_detection
        self._owned_locks: Set[Path] = set()  # Track locks held by this instance
        self._lock_registry: Dict[Path, LockInfo] = {}  # In-memory registry

        # Register cleanup on normal exit
        atexit.register(self._cleanup_owned_locks)

        # Attempt cleanup on signals (best effort)
        self._register_signal_handlers()

    def _register_signal_handlers(self):
        """Register signal handlers for emergency cleanup."""
        for sig in (signal.SIGTERM, signal.SIGINT):
            try:
                signal.signal(sig, self._signal_handler)
            except (ValueError, OSError):
                pass  # May fail in threads or Windows

    def _signal_handler(self, signum, frame):
        """Emergency cleanup on termination signals."""
        self._cleanup_owned_locks()
        # Re-raise default handler
        signal.default_int_handler(signum, frame)

    def _get_lock_path(self, path: Path) -> Path:
        """Determine lock file path for a target."""
        target = Path(path).resolve()

        if self.lock_dir:
            # Use centralized lock directory
            self.lock_dir.mkdir(parents=True, exist_ok=True)
            # Hash the path to avoid filesystem issues with long names
            path_hash = hex(hash(str(target)))[2:]
            return self.lock_dir / f"{target.name}.{path_hash}{self.LOCK_SUFFIX}"
        else:
            # Place lock next to target
            if target.is_dir():
                return target / f".operation{self.LOCK_SUFFIX}"
            else:
                return target.parent / f"{target.name}{self.LOCK_SUFFIX}"

    def _is_process_alive(self, pid: int) -> bool:
        """Check if a process is currently running."""
        if pid == os.getpid():
            return True  # We are alive (obviously)

        try:
            # Cross-platform process check
            process = psutil.Process(pid)
            # Additional check: ensure it's not a zombie
            return process.status() != psutil.STATUS_ZOMBIE
        except psutil.NoSuchProcess:
            return False
        except (psutil.AccessDenied, OSError):
            # Process exists but we can't access it - assume alive for safety
            return True

    def _is_lock_stale(self, lock_path: Path) -> bool:
        """Determine if a lock file is stale (orphaned by dead process)."""
        if not lock_path.exists():
            return False

        try:
            with open(lock_path, "r") as f:
                info = LockInfo.from_json(f.read())

            # Check if process is alive
            if not self._is_process_alive(info.pid):
                return True

            # Check timeout for very old locks (safety net)
            if time.time() - info.created_at > self.STALE_CHECK_TIMEOUT:
                # Double-check process is really gone
                if not self._is_process_alive(info.pid):
                    return True

            return False

        except (json.JSONDecodeError, IOError, OSError):
            # Corrupted lock file - treat as stale
            return True

    def _break_stale_lock(self, lock_path: Path) -> bool:
        """Remove a stale lock file."""
        try:
            lock_path.unlink(missing_ok=True)
            return True
        except OSError:
            return False

    def lock(self, path: Path, pid: int, operation: str = "operation") -> None:
        """
        Acquire a lock on path.

        Args:
            path: File or directory to lock
            pid: Process ID requesting the lock
            operation: Description of operation (for debugging)

        Raises:
            PermissionError: If lock is held by another live process
            RuntimeError: If this instance already holds the lock
        """
        target = Path(path).resolve()
        lock_path = self._get_lock_path(target)

        # Prevent double-locking by same instance
        if lock_path in self._owned_locks:
            raise RuntimeError(f"Lock already held by this instance: {target}", path)

        # Ensure parent directory exists
        lock_path.parent.mkdir(parents=True, exist_ok=True)

        # Try to acquire lock with stale detection
        while True:
            try:
                # Attempt exclusive creation (atomic on POSIX)
                fd = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)

                # We got the lock - write our info
                info = LockInfo(
                    pid=pid,
                    created_at=time.time(),
                    operation=operation,
                    target_path=str(target),
                )

                os.write(fd, info.to_json().encode("utf-8"))
                os.close(fd)

                # Track ownership
                self._owned_locks.add(lock_path)
                self._lock_registry[lock_path] = info

                return

            except FileExistsError:
                # Lock exists - check if stale
                if self.use_stale_detection and self._is_lock_stale(lock_path):
                    if self._break_stale_lock(lock_path):
                        continue  # Retry acquisition
                    else:
                        raise PermError(f"Cannot break stale lock: {lock_path}", path)
                else:
                    # Lock is valid and held by another process
                    holder_pid = self.get_lock_pid(target)
                    raise PermError(
                        f"Resource locked by process {holder_pid}: {target}", path
                    )

            except OSError as e:
                if e.errno == errno.EEXIST:
                    # Race condition - treat as FileExistsError
                    continue
                raise

    def unlock(self, path: Path, pid: int) -> None:
        """
        Release a lock on path.

        Args:
            path: File or directory to unlock
            pid: Process ID releasing the lock (must match locker)

        Raises:
            RuntimeError: If lock not owned by this PID
            FileNotFoundError: If lock doesn't exist
        """
        target = Path(path).resolve()
        lock_path = self._get_lock_path(target)

        if not lock_path.exists():
            # Clean up tracking even if file gone
            self._owned_locks.discard(lock_path)
            self._lock_registry.pop(lock_path, None)
            raise FileNotFoundError(f"Lock not found: {lock_path}")

        # Verify we own this lock
        try:
            with open(lock_path, "r") as f:
                info = LockInfo.from_json(f.read())

            if info.pid != pid:
                raise RuntimeError(
                    f"Lock owned by PID {info.pid}, cannot unlock from PID {pid}", path
                )

            if lock_path not in self._owned_locks:
                # Safety check: we didn't record owning this
                raise RuntimeError(
                    f"Lock not tracked by this instance (PID {pid})", path
                )

        except (json.JSONDecodeError, IOError) as e:
            raise RuntimeError(f"Cannot verify lock ownership: {e}")

        # Remove lock file
        try:
            lock_path.unlink()
        except OSError as e:
            raise RuntimeError(f"Failed to remove lock file: {e}", path)

        # Clean up tracking
        self._owned_locks.discard(lock_path)
        self._lock_registry.pop(lock_path, None)

    def is_locked(self, path: Path) -> bool:
        """
        Check if path is currently locked.

        Returns True if lock exists AND is held by a live process.
        Stale locks are automatically cleaned up.
        """
        target = Path(path).resolve()
        lock_path = self._get_lock_path(target)

        if not lock_path.exists():
            return False

        # Check if stale
        if self.use_stale_detection and self._is_lock_stale(lock_path):
            self._break_stale_lock(lock_path)
            return False

        return True

    def get_lock_pid(self, path: Path) -> Optional[int]:
        """
        Get the PID of the process holding the lock.

        Returns None if not locked or lock is stale (and cleaned up).
        """
        target = Path(path).resolve()
        lock_path = self._get_lock_path(target)

        if not lock_path.exists():
            return None

        try:
            with open(lock_path, "r") as f:
                info = LockInfo.from_json(f.read())

            # Verify process is still alive
            if self.use_stale_detection and not self._is_process_alive(info.pid):
                self._break_stale_lock(lock_path)
                return None

            return info.pid

        except (json.JSONDecodeError, IOError, OSError):
            # Corrupted lock file
            if self.use_stale_detection:
                self._break_stale_lock(lock_path)
            return None

    def get_lock_info(self, path: Path) -> Optional[LockInfo]:
        """Get full lock metadata if lock exists and is valid."""
        target = Path(path).resolve()
        lock_path = self._get_lock_path(target)

        if not self.is_locked(target):
            return None

        try:
            with open(lock_path, "r") as f:
                return LockInfo.from_json(f.read())
        except (json.JSONDecodeError, IOError):
            return None

    def _cleanup_owned_locks(self):
        """Release all locks held by this instance (atexit handler)."""
        # Copy set since unlock() modifies it
        locks_to_release = list(self._owned_locks)

        for lock_path in locks_to_release:
            try:
                # Find the original path from registry
                info = self._lock_registry.get(lock_path)
                if info:
                    self.unlock(Path(info.target_path), info.pid)
            except Exception:
                # Best effort cleanup - don't raise during exit
                try:
                    lock_path.unlink(missing_ok=True)
                except Exception:
                    pass

        self._owned_locks.clear()
        self._lock_registry.clear()

    def force_unlock(self, path: Path) -> bool:
        """
        Forcefully remove a lock (admin override).

        WARNING: Only use when you're certain the owning process is dead.
        """
        target = Path(path).resolve()
        lock_path = self._get_lock_path(target)

        try:
            lock_path.unlink(missing_ok=True)
            self._owned_locks.discard(lock_path)
            self._lock_registry.pop(lock_path, None)
            return True
        except OSError:
            return False

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - cleanup all locks."""
        self._cleanup_owned_locks()
        return False

    def __del__(self):
        """Finalizer - attempt cleanup."""
        self._cleanup_owned_locks()


# =============================================================================
# Windows Compatibility Alternative
# =============================================================================


class WindowsLockManager(LockManager):
    """
    Windows-specific implementation using file locking APIs.
    Falls back to LockManager behavior on non-Windows.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._windows_handles: Dict[Path, int] = {}

    def _get_lock_path(self, path: Path) -> Path:
        # Windows: use hidden file attribute
        lock_path = super()._get_lock_path(path)
        if os.name == "nt":
            # Ensure path is Windows-friendly
            return lock_path.resolve()
        return lock_path

    def lock(self, path: Path, pid: int, operation: str = "operation") -> None:
        if os.name != "nt":
            return super().lock(path, pid, operation)

        # Windows-specific implementation using msvcrt/ctypes could go here
        # For now, fall back to base implementation
        return super().lock(path, pid, operation)


# =============================================================================
# Convenience Decorator
# =============================================================================


def with_lock(manager: LockManager, operation: str = "operation"):
    """
    Decorator to automatically lock/unlock around a function.

    Usage:
        @with_lock(lock_manager, "encrypt")
        def encrypt_file(path: Path, key: bytes):
            ...
    """

    def decorator(func):
        def wrapper(path: Path, *args, **kwargs):
            pid = os.getpid()
            target = Path(path)

            manager.lock(target, pid, operation)
            try:
                return func(path, *args, **kwargs)
            finally:
                manager.unlock(target, pid)

        return wrapper

    return decorator


if __name__ == "__main__":
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        test_file = Path(tmp) / "secret.txt"
        test_file.write_text("sensitive data")

        manager = LockManager(use_stale_detection=True)

        # Basic usage
        print(f"Locked: {manager.is_locked(test_file)}")  # False

        manager.lock(test_file, os.getpid(), "encrypt")
        print(f"Locked: {manager.is_locked(test_file)}")  # True
        print(f"Lock PID: {manager.get_lock_pid(test_file)}")  # Current PID

        # Try to lock from same process (should fail)
        try:
            manager.lock(test_file, os.getpid(), "encrypt")
        except RuntimeError as e:
            print(f"Double-lock prevented: {e}")

        # Check info
        info = manager.get_lock_info(test_file)
        print(f"Operation: {info.operation}")  # "encrypt"

        manager.unlock(test_file, os.getpid())
        print(f"Locked after unlock: {manager.is_locked(test_file)}")  # False

        # Context manager usage
        with LockManager() as mgr:
            mgr.lock(test_file, os.getpid(), "process")
            # Auto-unlocks on exit
