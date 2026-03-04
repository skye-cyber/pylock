class SuiteError(Exception):
    """
    Encryptionsuite base error
    """


class SuiteExit(Exception.KeyboardInterrupt):
    """
    System Exit handler
    """


class KeyError:
    """
    Handle error related to encryption/decryption key
    """


class ValidationError(SuiteError):
    """Raised when validation fails."""

    pass


class SystemPermissionError(SuiteError):
    """
    Raised when user cannot acess to system reasource due to insuficient permissions.
    Eg command execusion
    """

    pass


class FileSystemError(SuiteError):
    """
    Raises when there is file/folder ie FileSystem acess error not related to permissions.
    ie write error
    """

    pass


class AuthorizationError(SuiteError):
    """
    Raised when there is an *Explicit* file/dir/resource access denial.
        When priviledge elevelation is required.
    """

    pass


class ConfigurationError(SuiteError):
    """Raised when invalid configuration."""

    pass
