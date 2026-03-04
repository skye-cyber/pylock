"""
PyLock Exception Hierarchy

Structure:
- PyLockError (base)
  - UserError (user mistakes)
    - ValidationError
    - ConfigurationError
    - KeyError
  - SystemError (environment issues)
    - FileSystemError
    - SystemPermissionError
    - AuthorizationError
  - SuiteExit (clean exit, not an error)
"""

import errno
from typing import Optional, Dict, Any


class PyLockError(Exception):
    """
    Base exception for all EncryptionSuite errors.

    Attributes:
        message: Human-readable error description
        code: Optional error code for programmatic handling
        details: Additional context dictionary
    """

    def __init__(
        self,
        message: str,
        code: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ):
        super().__init__(message)
        self.message = message
        self.code = code or self.__class__.__name__
        self.details = details or {}

    def __str__(self) -> str:
        if self.details:
            return f"{self.message} (details: {self.details})"
        return self.message

    def to_dict(self) -> Dict[str, Any]:
        """Serialize error for logging/API responses."""
        return {
            "error": self.code,
            "message": self.message,
            "details": self.details,
            "type": self.__class__.__name__,
        }


class UserError(PyLockError):
    """
    Errors caused by user input or configuration.
    These are typically recoverable by user action.
    """

    pass


class SystemError(PyLockError):
    """
    Errors caused by system/environment conditions.
    May require system administrator intervention.
    """

    pass


# =============================================================================
# User Errors
# =============================================================================


class ValidationError(UserError):
    """Raised when input validation fails."""

    def __init__(self, message: str, field: Optional[str] = None, value: Any = None):
        details = {}
        if field:
            details["field"] = field
        if value is not None:
            details["value"] = repr(value)
        super().__init__(message, details=details)


class ConfigurationError(UserError):
    """Raised when configuration is invalid or missing."""

    def __init__(
        self,
        message: str,
        config_key: Optional[str] = None,
        config_file: Optional[str] = None,
    ):
        details = {}
        if config_key:
            details["config_key"] = config_key
        if config_file:
            details["config_file"] = config_file
        super().__init__(message, details=details)


class KeyError(UserError):  # Shadowing built-in KeyError, see note below
    """
    Errors related to encryption/decryption keys.

    Note: This shadows built-in KeyError. Use 'from suite.exceptions import KeyError'
    or reference as 'suite.exceptions.KeyError' to avoid conflicts.
    """

    def __init__(
        self,
        message: str,
        key_id: Optional[str] = None,
        key_file: Optional[str] = None,
        reason: Optional[str] = None,  # 'missing', 'invalid', 'expired', 'corrupted'
    ):
        details = {}
        if key_id:
            details["key_id"] = key_id
        if key_file:
            details["key_file"] = key_file
        if reason:
            details["reason"] = reason
        super().__init__(message, details=details)


# =============================================================================
# System Errors
# =============================================================================


class FileSystemError(SystemError):
    """
    Raised when file system operations fail (not permission-related).
    Examples: disk full, file not found, I/O errors.
    """

    def __init__(
        self,
        message: str,
        path: Optional[str] = None,
        operation: Optional[str] = None,  # 'read', 'write', 'delete', etc.
        errno_code: Optional[int] = None,
    ):
        details = {}
        if path:
            details["path"] = str(path)
        if operation:
            details["operation"] = operation
        if errno_code:
            details["errno"] = errno_code
            # Auto-enhance message with standard error description
            if not message.endswith("."):
                message += "."
            message += f" [{errno.errorcode.get(errno_code, 'UNKNOWN')}]"

        super().__init__(message, details=details)

    @classmethod
    def from_os_error(
        cls, os_error: OSError, operation: Optional[str] = None
    ) -> "FileSystemError":
        """Factory method to create from OSError."""
        return cls(
            message=str(os_error),
            path=os_error.filename,
            operation=operation,
            errno_code=os_error.errno,
        )


class RuntimeError(RuntimeError):
    """
    Raised runtime erros.
    """

    def __init__(
        self,
        message: str,
        path: Optional[str] = None,
    ):
        details = {}
        if path:
            details["path"] = str(path)
        super().__init__(message, details=details)


class SystemPermissionError(SystemError):
    """
    Raised when OS-level permissions prevent access.
    Different from AuthorizationError: this is about *system* permissions (chmod),
    not *application* authorization (ACLs, authentication).
    """

    def __init__(
        self,
        message: str,
        path: Optional[str] = None,
        required: Optional[str] = None,  # 'read', 'write', 'execute'
        current: Optional[str] = None,  # current permissions, e.g., 'r--'
    ):
        details = {}
        if path:
            details["path"] = str(path)
        if required:
            details["required_permission"] = required
        if current:
            details["current_permission"] = current
        super().__init__(message, details=details)


class AuthorizationError(SystemError):
    """
    Raised when explicitly denied access to a resource.
    This is about *authorization* (who you are), not *permissions* (what system allows).
    Examples: password required, privilege escalation needed, token expired.
    """

    def __init__(
        self,
        message: str,
        resource: Optional[str] = None,
        action: Optional[str] = None,  # what was attempted
        auth_type: Optional[str] = None,  # 'password', 'token', 'certificate', 'sudo'
    ):
        details = {}
        if resource:
            details["resource"] = resource
        if action:
            details["action"] = action
        if auth_type:
            details["auth_type"] = auth_type
        super().__init__(message, details=details)


# =============================================================================
# Control Flow Exceptions (Not Errors)
# =============================================================================


class SuiteExit(BaseException):
    """
    Clean exit signal for the application.

    Note: Inherits from BaseException, not Exception, to avoid being caught
    by generic 'except Exception' handlers. This ensures clean shutdown.

    Do NOT catch this unless you are the main entry point.
    """

    def __init__(self, code: int = 0, message: Optional[str] = None):
        self.code = code
        self.message = message or "Application exited cleanly"
        super().__init__(self.message)

    def __str__(self) -> str:
        return f"Exit({self.code}): {self.message}"


# Alias for cleaner imports
Exit = SuiteExit
ConfigError = ConfigurationError
PermError = SystemPermissionError
AuthError = AuthorizationError
