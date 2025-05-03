class BWSException(Exception):
    """Base class for BWS exceptions."""
    pass


class BWSExecutableNotFound(BWSException):
    """Raised when the Bitwarden CLI executable is not found."""
    pass


class BWSInvalidProjectName(BWSException):
    """Raised when the project name is invalid."""
    pass


class BWSProjectCreateFailed(BWSException):
    """Raised when the project creation fails."""
    pass


class BWSProjectExists(BWSException):
    """Raised when the project name already exists."""
    pass


class BWSProjectNotFound(BWSException):
    """Raised when the project name is not found."""
    pass


class BWSAccessTokenNotFound(BWSException):
    """Raised when the access token is not found."""
    pass


class BWSKeyExistsException(BWSException):
    """Raised when the key already exists in the project."""
    pass


class BWSKeyInvalid(BWSException):
    """Raised when the key is invalid."""
    pass


class BWSKeyNotFound(BWSException):
    """Raised when the key is not found."""
    pass


class BWSKeyUpdateFailed(BWSException):
    """Raised when the key update fails."""
    pass


class BWSKeyDeleteFailed(BWSException):
    """Raised when the key delete fails."""
    pass


class BWSKeyCreateFailed(BWSException):
    """Raised when the key creation fails."""
    pass


class BWSKeyListFailed(BWSException):
    """Raised when the key list fails."""
    pass


class BWSKeyEditFailed(BWSException):
    """Raised when the key edit fails."""
    pass


class BWSExecutionException(BWSException):
    """Raised when the Bitwarden CLI command execution fails."""
    pass
